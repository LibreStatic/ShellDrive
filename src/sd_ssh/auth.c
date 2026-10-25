/* User authentication (RFC 4252, RFC 4256; 01 §6.1, §6.2, §6.4). M0: none, publickey with Ed25519
 * key files (OpenSSH v1, unencrypted or bcrypt), keyboard-interactive and password.
 * I/O thread only; key files are read and decrypted on worker items. */
#include <windows.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "conn_internal.h"

#define AUTH_MAX_PK_ATTEMPTS 6u
#define AUTH_MAX_ROUNDS 3u
#define AUTH_MAX_PASS_TRIES 3u

static void auth_next(sd_ssh_conn *c);

void ssh_auth_clear(sd_ssh_conn *c)
{
  ssh_auth *a = &c->auth;
  sd_secbuf_free(a->key_file);
  a->key_file = NULL;
  sd_ssh_key_free(a->key);
  a->key = NULL;
  sd_secbuf_free(a->pw_pending);
  a->pw_pending = NULL;
  sd_secbuf_free(a->pp_pending);
  a->pp_pending = NULL;
}

static void write_req_head(sd_ssh_conn *c, sd_wr *w, const char *method)
{
  sd_wr_u8(w, SSH_MSG_USERAUTH_REQUEST);
  sd_wr_cstring(w, c->user);
  sd_wr_cstring(w, "ssh-connection");
  sd_wr_cstring(w, method);
}

void ssh_auth_start(sd_ssh_conn *c)
{
  sd_wr w;
  c->st = SSH_ST_AUTH;
  memset(&c->auth, 0, sizeof(c->auth));
  c->auth.step = SSH_AU_NONE;
  sd_wr_init(&w, 4096);
  write_req_head(c, &w, "none");
  ssh_send_wr(c, &w);
}

static int server_allows(sd_ssh_conn *c, const char *m) { return ssh_csv_contains(c->auth.methods, m); }

/* ---- prompts ---- */

static sd_prompt *new_auth_prompt(sd_ssh_conn *c, ssh_prompt_purpose pp, sd_prompt_kind kind, uint32_t round)
{
  sd_prompt *p = ssh_prompt_new(c, pp, kind);
  if (!p) { ssh_fail(c, SD_E_NO_MEMORY, SSH_DISCONNECT_BY_APPLICATION, "prompt"); return NULL; }
  ssh_prompt_auth_info(p)->round = round;
  return p;
}

static void send_password(sd_ssh_conn *c, const sd_secbuf *pw)
{
  sd_wr w;
  sd_wr_init_secret(&w, 8192);
  write_req_head(c, &w, "password");
  sd_wr_bool(&w, 0);
  sd_wr_string(&w, pw->p, pw->len);
  c->auth.step = SSH_AU_PASSWORD;
  ssh_send_wr(c, &w);
}

/* Reconnect cache (01 §7.4): answers the first password round itself. Returns 1 when sent. */
static int password_from_cache(sd_ssh_conn *c)
{
  sd_secbuf *pw = NULL;
  if (!ssh_cache_usable(c) || c->auth.pw_cache_tried || c->auth.password_rounds != 0 || !c->cache.password.blob)
    return 0;
  c->auth.pw_cache_tried = 1;
  if (ssh_secret_load(&c->cache.password, &pw) != SD_OK) return 0;
  ssh_log(c, SD_LOG_INFO, "password: using the reconnect cache");
  c->auth.pw_from_cache = 1;
  send_password(c, pw);
  sd_secbuf_free(pw);
  return 1;
}

static void prompt_password(sd_ssh_conn *c)
{
  sd_prompt *p;
  sd_prompt_item *it;
  sd_auth_prompt_info *ai;
  if (password_from_cache(c)) return;
  p = new_auth_prompt(c, SSH_PP_PASSWORD, SD_PROMPT_PASSWORD, c->auth.password_rounds);
  if (!p) return;
  ai = ssh_prompt_auth_info(p);
  it = ssh_prompt_items(p, 1);
  it[0].text = "Password: ";
  it[0].echo = 0;
  ai->may_autofill = c->auth.password_rounds == 0 && !c->hostkey_just_accepted;
  c->auth.step = SSH_AU_PROMPT;
  ssh_prompt_raise(c, p);
}

static const ssh_ident *cur_ident(sd_ssh_conn *c) { return &c->ids[c->auth.id_next - 1]; }

static void start_load(sd_ssh_conn *c, sd_secbuf *pass);

/* Reconnect cache: the passphrase that decrypted this identity before. Returns 1 when used. */
static int passphrase_from_cache(sd_ssh_conn *c)
{
  uint32_t idx = c->auth.id_next - 1;
  sd_secbuf *pp = NULL;
  if (!ssh_cache_usable(c) || c->auth.pp_cache_tried || idx >= c->cache.npass || !c->cache.pass[idx].blob) return 0;
  c->auth.pp_cache_tried = 1;
  if (ssh_secret_load(&c->cache.pass[idx], &pp) != SD_OK) return 0;
  ssh_log(c, SD_LOG_INFO, "key passphrase: using the reconnect cache");
  c->auth.pp_from_cache = 1;
  start_load(c, pp);
  return 1;
}

static void prompt_passphrase(sd_ssh_conn *c)
{
  const ssh_ident *id = cur_ident(c);
  sd_prompt *p;
  sd_prompt_item *it;
  sd_auth_prompt_info *ai;
  if (passphrase_from_cache(c)) return;
  p = new_auth_prompt(c, SSH_PP_PASSPHRASE, SD_PROMPT_KEY_PASSPHRASE, c->auth.pass_tries);
  if (!p) return;
  ai = ssh_prompt_auth_info(p);
  it = ssh_prompt_items(p, 1);
  it[0].text = "Passphrase: ";
  it[0].echo = 0;
  ai->key_path = ssh_prompt_str(p, id->kind == SD_ID_FILE ? id->path_utf8 : id->label);
  ai->key_fingerprint = ssh_prompt_str(p, c->auth.cand_fp);
  ai->may_autofill = c->auth.pass_tries == 0;   /* passphrases are unaffected by TM-R05 */
  ai->hostkey_just_accepted = 0;
  c->auth.step = SSH_AU_PROMPT;
  ssh_prompt_raise(c, p);
}

/* ---- key file workers ---- */

typedef struct key_work {
  ssh_work w;
  int load;
  wchar_t path[MAX_PATH + 1];
  int from_file;
  sd_secbuf *bytes;           /* in (blob) / out (file contents) */
  sd_secbuf *pass;            /* load: passphrase or NULL */
  sd_ssh_key_probe_info info;
  sd_ssh_key *key;
  sd_err err;
} key_work;

static sd_err read_key_file(const wchar_t *path, sd_secbuf **out)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  DWORD got = 0;
  sd_err e;
  if (h == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_NOT_FOUND;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 1024 * 1024) { CloseHandle(h); return SD_E_KEY_FORMAT; }
  e = sd_secbuf_new((size_t)sz.QuadPart, out);
  if (e != SD_OK) { CloseHandle(h); return e; }
  if (!ReadFile(h, (*out)->p, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart) {
    CloseHandle(h);
    sd_secbuf_free(*out);
    *out = NULL;
    return SD_E_FAILURE;
  }
  CloseHandle(h);
  (*out)->len = got;
  return SD_OK;
}

static void key_do(ssh_work *w)
{
  key_work *k = (key_work *)w;
  if (!k->load) {
    if (k->from_file) {
      k->err = read_key_file(k->path, &k->bytes);
      if (k->err != SD_OK) return;
    }
    k->err = sd_ssh_key_probe(k->bytes->p, k->bytes->len, &k->info);
  } else {
    k->err = sd_ssh_key_load(k->bytes->p, k->bytes->len, k->pass ? (const char *)k->pass->p : NULL,
                             k->pass ? k->pass->len : 0, &k->key);
  }
}

static void key_free(key_work *k)
{
  sd_secbuf_free(k->bytes);
  sd_secbuf_free(k->pass);
  sd_ssh_key_free(k->key);
  sd_free(k);
}

static void key_drop(ssh_cmd *cmd) { key_free((key_work *)cmd); }

static void send_pk(sd_ssh_conn *c, const uint8_t *sig, size_t sig_len)
{
  sd_wr w;
  sd_wr_init(&w, 8192);
  write_req_head(c, &w, "publickey");
  sd_wr_bool(&w, sig != NULL);
  sd_wr_cstring(&w, "ssh-ed25519");
  sd_wr_string(&w, c->auth.cand_blob, c->auth.cand_len);
  if (sig) sd_wr_string(&w, sig, sig_len);
  ssh_send_wr(c, &w);
}

static void sign_and_send(sd_ssh_conn *c)
{
  sd_wr d;
  uint8_t sig[128];
  size_t sig_len = 0;
  sd_err e;
  sd_wr_init_secret(&d, 8192);
  sd_wr_string(&d, c->session_id, c->session_id_len);
  write_req_head(c, &d, "publickey");
  sd_wr_bool(&d, 1);
  sd_wr_cstring(&d, "ssh-ed25519");
  sd_wr_string(&d, c->auth.cand_blob, c->auth.cand_len);
  e = sd_wr_ok(&d) ? sd_ssh_key_sign(c->auth.key, d.p, d.len, sig, sizeof(sig), &sig_len) : SD_E_NO_MEMORY;
  sd_wr_free(&d);
  sd_ssh_key_free(c->auth.key);
  c->auth.key = NULL;
  if (e != SD_OK) {
    ssh_log(c, SD_LOG_WARN, "signing with %s failed: %s", c->auth.cand_fp, sd_err_name(e));
    auth_next(c);
    return;
  }
  c->auth.step = SSH_AU_PK_SIGN;
  send_pk(c, sig, sig_len);
}

static void load_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  key_work *k = (key_work *)cmd;
  if (k->w.gen != c->gen || c->failing || c->st != SSH_ST_AUTH || c->auth.step != SSH_AU_PK_LOAD) { key_free(k); return; }
  if (c->auth.pp_from_cache) {
    c->auth.pp_from_cache = 0;
    if (k->err == SD_E_BAD_PASSPHRASE) {    /* stale cache entry: drop it, ask normally (not a try) */
      uint32_t idx = c->auth.id_next - 1;
      if (idx < c->cache.npass) ssh_secret_clear(&c->cache.pass[idx]);
      key_free(k);
      prompt_passphrase(c);
      return;
    }
  }
  if (k->err == SD_OK && c->auth.pp_pending) {
    uint32_t idx = c->auth.id_next - 1;
    if (ssh_cache_usable(c) && idx < c->cache.npass &&
        ssh_secret_store(&c->cache.pass[idx], c->auth.pp_pending->p, c->auth.pp_pending->len) != SD_OK)
      ssh_log(c, SD_LOG_WARN, "reconnect cache unavailable; the passphrase is not kept");
  }
  sd_secbuf_free(c->auth.pp_pending);
  c->auth.pp_pending = NULL;
  if (k->err == SD_E_BAD_PASSPHRASE && ++c->auth.pass_tries < AUTH_MAX_PASS_TRIES) {
    key_free(k);
    prompt_passphrase(c);
    return;
  }
  if (k->err != SD_OK) {
    ssh_log(c, SD_LOG_WARN, "key %s unusable: %s", c->auth.cand_fp, sd_err_name(k->err));
    key_free(k);
    auth_next(c);
    return;
  }
  c->auth.key = k->key;
  k->key = NULL;
  key_free(k);
  sign_and_send(c);
}

static void start_load(sd_ssh_conn *c, sd_secbuf *pass)
{
  key_work *k = (key_work *)sd_calloc(1, sizeof(*k));
  sd_err e;
  if (!k) { sd_secbuf_free(pass); ssh_fail(c, SD_E_NO_MEMORY, 0, "auth"); return; }
  k->load = 1;
  k->pass = pass;
  e = sd_secbuf_from(c->auth.key_file->p, c->auth.key_file->len, &k->bytes);
  if (e != SD_OK) { key_free(k); ssh_fail(c, e, 0, "auth"); return; }
  k->w.cmd.run = load_done;
  k->w.cmd.drop = key_drop;
  k->w.work = key_do;
  c->auth.step = SSH_AU_PK_LOAD;
  if (ssh_queue_work(c, &k->w) != SD_OK) { key_free(k); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
}

static void probe_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  key_work *k = (key_work *)cmd;
  if (k->w.gen != c->gen || c->failing || c->st != SSH_ST_AUTH || c->auth.step != SSH_AU_PK_PROBE) { key_free(k); return; }
  if (k->err != SD_OK || strcmp(k->info.type, "ssh-ed25519") != 0 || k->info.pub_len > sizeof(c->auth.cand_blob)) {
    ssh_log(c, SD_LOG_INFO, "identity %u skipped: %s", c->auth.id_next,
            k->err != SD_OK ? sd_err_name(k->err) : "key type not supported in this version");
    key_free(k);
    auth_next(c);
    return;
  }
  sd_secbuf_free(c->auth.key_file);
  c->auth.key_file = k->bytes;
  k->bytes = NULL;
  memcpy(c->auth.cand_blob, k->info.pub_blob, k->info.pub_len);
  c->auth.cand_len = k->info.pub_len;
  memcpy(c->auth.cand_fp, k->info.fp_sha256, sizeof(c->auth.cand_fp));
  c->auth.cand_encrypted = k->info.encrypted;
  c->auth.pass_tries = 0;
  c->auth.pp_cache_tried = 0;
  key_free(k);
  c->auth.pk_attempts++;
  c->auth.step = SSH_AU_PK_QUERY;
  ssh_log(c, SD_LOG_DEBUG, "offering key %s", c->auth.cand_fp);
  send_pk(c, NULL, 0);
}

static void start_identity(sd_ssh_conn *c)
{
  const ssh_ident *id = &c->ids[c->auth.id_next++];
  key_work *k = (key_work *)sd_calloc(1, sizeof(*k));
  sd_err e = SD_OK;
  if (!k) { ssh_fail(c, SD_E_NO_MEMORY, 0, "auth"); return; }
  if (id->kind == SD_ID_FILE) {
    size_t n = wcslen(id->path);
    if (n >= SD_COUNTOF(k->path)) { sd_free(k); auth_next(c); return; }
    memcpy(k->path, id->path, (n + 1) * sizeof(wchar_t));
    k->from_file = 1;
  } else {
    e = sd_secbuf_from(id->blob->p, id->blob->len, &k->bytes);
  }
  if (e != SD_OK) { key_free(k); ssh_fail(c, e, 0, "auth"); return; }
  k->w.cmd.run = probe_done;
  k->w.cmd.drop = key_drop;
  k->w.work = key_do;
  c->auth.step = SSH_AU_PK_PROBE;
  if (ssh_queue_work(c, &k->w) != SD_OK) { key_free(k); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
}

/* ---- method selection (01 §6.1) ---- */

static void auth_next(sd_ssh_conn *c)
{
  ssh_auth *a = &c->auth;
  if (c->failing) return;
  if ((c->methods & SD_AUTH_PUBLICKEY) && server_allows(c, "publickey") && !a->partial_pk &&
      a->id_next < c->id_count && a->pk_attempts < AUTH_MAX_PK_ATTEMPTS) {
    start_identity(c);
    return;
  }
  if ((c->methods & SD_AUTH_KBDINT) && server_allows(c, "keyboard-interactive") && !a->partial_kbd &&
      a->kbd_rounds < AUTH_MAX_ROUNDS) {
    sd_wr w;
    sd_wr_init(&w, 4096);
    write_req_head(c, &w, "keyboard-interactive");
    sd_wr_cstring(&w, "");   /* language */
    sd_wr_cstring(&w, "");   /* submethods */
    a->step = SSH_AU_KBDINT;
    ssh_send_wr(c, &w);
    return;
  }
  if ((c->methods & SD_AUTH_PASSWORD) && server_allows(c, "password") && !a->partial_pw &&
      a->password_rounds < AUTH_MAX_ROUNDS) {
    prompt_password(c);
    return;
  }
  {
    char m[256];
    ssh_sanitize((const uint8_t *)a->methods, strlen(a->methods), m, sizeof(m));
    ssh_log(c, SD_LOG_WARN, "authentication failed; server still offers: %s", m);
  }
  ssh_fail(c, SD_E_AUTH_FAILED, SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "no more authentication methods");
}

/* A user-answered password worked (fully or partially): keep it for reconnects (01 §7.4). */
static void store_password(sd_ssh_conn *c)
{
  if (c->auth.pw_pending && ssh_cache_usable(c) &&
      ssh_secret_store(&c->cache.password, c->auth.pw_pending->p, c->auth.pw_pending->len) != SD_OK)
    ssh_log(c, SD_LOG_WARN, "reconnect cache unavailable; the password is not kept");
  sd_secbuf_free(c->auth.pw_pending);
  c->auth.pw_pending = NULL;
}

static void on_failure(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  ssh_auth *a = &c->auth;
  sd_rd r;
  sd_span list;
  int partial;
  sd_rd_init(&r, p + 1, n - 1);
  list = sd_rd_name_list(&r, 4096);
  partial = sd_rd_bool(&r);
  if (!sd_rd_ok(&r)) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad USERAUTH_FAILURE"); return; }
  if (!ssh_span_copy(list, a->methods, sizeof(a->methods))) a->methods[0] = '\0';
  switch (a->step) {
  case SSH_AU_PK_SIGN:
    if (partial) { a->partial_pk = 1; c->methods_used |= SD_AUTH_PUBLICKEY; }
    break;
  case SSH_AU_PASSWORD:
    if (partial) { a->partial_pw = 1; c->methods_used |= SD_AUTH_PASSWORD; store_password(c); }
    else if (a->pw_from_cache) {   /* the cached password no longer works: drop it, prompt (not a round) */
      ssh_log(c, SD_LOG_INFO, "cached password rejected; dropped from the reconnect cache");
      ssh_secret_clear(&c->cache.password);
    } else a->password_rounds++;
    a->pw_from_cache = 0;
    sd_secbuf_free(a->pw_pending);
    a->pw_pending = NULL;
    break;
  case SSH_AU_KBDINT:
    if (partial) { a->partial_kbd = 1; c->methods_used |= SD_AUTH_KBDINT; }
    else a->kbd_rounds++;
    break;
  default:
    break;
  }
  if (a->step == SSH_AU_PK_SIGN || a->step == SSH_AU_PK_QUERY) {
    sd_secbuf_free(a->key_file);
    a->key_file = NULL;
  }
  auth_next(c);
}

static void on_info_request(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  sd_rd r;
  sd_span name, instr, txt[16];
  int echo[16];
  uint32_t np, i;
  sd_rd_init(&r, p + 1, n - 1);
  name = sd_rd_string(&r, 1024);
  instr = sd_rd_string(&r, 4096);
  (void)sd_rd_string(&r, 256);
  np = sd_rd_u32(&r);
  if (np > 16) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "too many prompts"); return; }
  for (i = 0; i < np; i++) { txt[i] = sd_rd_string(&r, 1024); echo[i] = sd_rd_bool(&r); }
  if (!sd_rd_ok(&r)) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad INFO_REQUEST"); return; }
  if (np == 0) {   /* "press enter" rounds are answered at once (01 §6.4) */
    uint8_t b[8];
    b[0] = SSH_MSG_USERAUTH_INFO_RESPONSE;
    sd_store_be32(b + 1, 0);
    ssh_send(c, b, 5);
    return;
  }
  {
    sd_prompt *pr = new_auth_prompt(c, SSH_PP_KBDINT, SD_PROMPT_KBDINT, c->auth.kbd_rounds);
    sd_auth_prompt_info *ai;
    sd_prompt_item *it;
    char buf[3 * 1024 + 1];
    if (!pr) return;
    ai = ssh_prompt_auth_info(pr);
    it = ssh_prompt_items(pr, np);
    ssh_sanitize(name.p, name.n, buf, sizeof(buf));
    ai->name = ssh_prompt_str(pr, buf);
    ssh_sanitize(instr.p, instr.n, buf, sizeof(buf));
    ai->instruction = ssh_prompt_str(pr, buf);
    for (i = 0; i < np; i++) {
      ssh_sanitize(txt[i].p, txt[i].n, buf, sizeof(buf));
      it[i].text = ssh_prompt_str(pr, buf);
      it[i].echo = echo[i];
    }
    ai->may_autofill = np == 1 && !echo[0] && c->auth.kbd_rounds == 0 && !c->hostkey_just_accepted;
    c->auth.step = SSH_AU_PROMPT;
    ssh_prompt_raise(c, pr);
  }
}

void ssh_auth_on_msg(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  uint8_t m = p[0];
  switch (m) {
  case SSH_MSG_USERAUTH_SUCCESS:
    if (c->auth.step == SSH_AU_PK_SIGN) c->methods_used |= SD_AUTH_PUBLICKEY;
    else if (c->auth.step == SSH_AU_PASSWORD) { c->methods_used |= SD_AUTH_PASSWORD; store_password(c); }
    else if (c->auth.step == SSH_AU_KBDINT) c->methods_used |= SD_AUTH_KBDINT;
    ssh_on_authenticated(c);
    return;
  case SSH_MSG_USERAUTH_FAILURE:
    on_failure(c, p, n);
    return;
  case SSH_MSG_USERAUTH_BANNER: {
    sd_rd r;
    sd_span msg;
    char *buf;
    sd_rd_init(&r, p + 1, n - 1);
    msg = sd_rd_string(&r, 64 * 1024);
    if (!sd_rd_ok(&r)) return;
    if (msg.n > 16 * 1024) msg.n = 16 * 1024;
    buf = (char *)sd_alloc(msg.n * 3 + 1);
    if (!buf) return;
    ssh_sanitize(msg.p, msg.n, buf, msg.n * 3 + 1);
    if (c->cb.on_banner) c->cb.on_banner(c->cb.ctx, 0, buf);
    sd_free(buf);
    return;
  }
  case 60:
    if (c->auth.step == SSH_AU_PK_QUERY) {        /* PK_OK */
      if (c->auth.cand_encrypted) prompt_passphrase(c);
      else start_load(c, NULL);
      return;
    }
    if (c->auth.step == SSH_AU_KBDINT) { on_info_request(c, p, n); return; }
    if (c->auth.step == SSH_AU_PASSWORD) {        /* PASSWD_CHANGEREQ: M2 */
      ssh_log(c, SD_LOG_WARN, "server requests a password change (not supported yet)");
      c->auth.password_rounds = AUTH_MAX_ROUNDS;
      auth_next(c);
      return;
    }
    break;
  default:
    break;
  }
  ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "unexpected userauth message");
}

void ssh_auth_on_answer(sd_ssh_conn *c, ssh_prompt_purpose pp, ssh_prompt_answer *a)
{
  if (c->st != SSH_ST_AUTH || c->auth.step != SSH_AU_PROMPT) return;
  if (pp == SSH_PP_PASSPHRASE) {
    sd_secbuf *pass = NULL;
    if (a->cancelled || a->n != 1) { auth_next(c); return; }   /* skip this key */
    pass = a->resp[0];
    a->resp[0] = NULL;
    a->n = 0;
    sd_secbuf_free(c->auth.pp_pending);
    c->auth.pp_pending = NULL;
    if (ssh_cache_usable(c) && sd_secbuf_from(pass->p, pass->len, &c->auth.pp_pending) != SD_OK)
      c->auth.pp_pending = NULL;
    start_load(c, pass);
    return;
  }
  if (a->cancelled) {
    ssh_fail(c, SD_E_CANCELLED, SSH_DISCONNECT_BY_APPLICATION, "authentication cancelled");
    return;
  }
  if (pp == SSH_PP_PASSWORD) {
    if (a->n != 1) { ssh_fail(c, SD_E_CANCELLED, SSH_DISCONNECT_BY_APPLICATION, "no password"); return; }
    sd_secbuf_free(c->auth.pw_pending);
    c->auth.pw_pending = NULL;
    if (ssh_cache_usable(c) && sd_secbuf_from(a->resp[0]->p, a->resp[0]->len, &c->auth.pw_pending) != SD_OK)
      c->auth.pw_pending = NULL;
    c->auth.pw_from_cache = 0;
    send_password(c, a->resp[0]);
    return;
  }
  if (pp == SSH_PP_KBDINT) {
    sd_wr w;
    uint32_t i;
    sd_wr_init_secret(&w, 64 * 1024);
    sd_wr_u8(&w, SSH_MSG_USERAUTH_INFO_RESPONSE);
    sd_wr_u32(&w, a->n);
    for (i = 0; i < a->n; i++) sd_wr_string(&w, a->resp[i]->p, a->resp[i]->len);
    c->auth.step = SSH_AU_KBDINT;
    ssh_send_wr(c, &w);
  }
}
