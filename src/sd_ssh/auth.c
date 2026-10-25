/* User authentication (RFC 4252, RFC 4256, RFC 8332; 01 §6.1-§6.5). none, then publickey (key
 * files and blobs in every supported format, OpenSSH user certificates, Pageant and OpenSSH-agent
 * keys; RSA with rsa-sha2-512/256 per server-sig-algs), keyboard-interactive (multi-round, OTP) and
 * password (with SSH_MSG_USERAUTH_PASSWD_CHANGEREQ). I/O thread only; key files are read, decrypted
 * and signed with on worker items, agents are queried there too. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_ssh/sd_agent.h"
#include "sd_ssh/sd_known_hosts.h"
#include "agent_internal.h"
#include "conn_internal.h"
#include "keyfile_internal.h"

#define AUTH_MAX_PK_ATTEMPTS 6u
#define AUTH_MAX_ROUNDS 3u
#define AUTH_MAX_PASS_TRIES 3u
#define AUTH_MAX_CANDS 64u
#define AUTH_MAX_INFO_ROUNDS 16u
#define AUTH_NO_IDENT 0xFFFFFFFFu

static void auth_next(sd_ssh_conn *c);
static void send_query(sd_ssh_conn *c);
static void start_sign(sd_ssh_conn *c);

/* ---- state ---- */

static void cands_free(ssh_auth *a)
{
  uint32_t i;
  for (i = 0; i < a->ncand; i++) {
    sd_free(a->cand[i].blob);
    sd_free(a->cand[i].sign_blob);
  }
  sd_free(a->cand);
  a->cand = NULL;
  a->ncand = a->cand_next = 0;
}

static void pk_release(ssh_auth *a)
{
  uint32_t i;
  cands_free(a);
  for (i = 0; i < a->nid; i++) {
    if (a->idfile) sd_secbuf_free(a->idfile[i]);
    if (a->idkey) sd_ssh_key_free(a->idkey[i]);
  }
  sd_free(a->idfile);
  sd_free(a->idkey);
  sd_free(a->idenc);
  a->idfile = NULL;
  a->idkey = NULL;
  a->idenc = NULL;
  a->nid = 0;
}

void ssh_auth_clear(sd_ssh_conn *c)
{
  ssh_auth *a = &c->auth;
  pk_release(a);
  sd_secbuf_free(a->pw_pending);
  a->pw_pending = NULL;
  sd_secbuf_free(a->pp_pending);
  a->pp_pending = NULL;
  sd_secure_zero(a->pwchange_prompt, sizeof(a->pwchange_prompt));
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
  ssh_auth_clear(c);
  c->st = SSH_ST_AUTH;
  memset(&c->auth, 0, sizeof(c->auth));
  c->auth.step = SSH_AU_NONE;
  sd_wr_init(&w, 4096);
  write_req_head(c, &w, "none");
  ssh_send_wr(c, &w);
}

static int server_allows(sd_ssh_conn *c, const char *m) { return ssh_csv_contains(c->auth.methods, m); }

static ssh_cand *cur_cand(sd_ssh_conn *c) { return &c->auth.cand[c->auth.cand_next - 1]; }

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

/* SSH_MSG_USERAUTH_PASSWD_CHANGEREQ (RFC 4252 §8): current, new and confirm (01 §6.1 rule 5). */
static void prompt_new_password(sd_ssh_conn *c, const char *note)
{
  sd_prompt *p;
  sd_prompt_item *it;
  sd_auth_prompt_info *ai;
  p = new_auth_prompt(c, SSH_PP_PASSWORD, SD_PROMPT_NEW_PASSWORD, c->auth.pwchange_rounds);
  if (!p) return;
  ai = ssh_prompt_auth_info(p);
  ai->name = "";
  ai->instruction = ssh_prompt_str(p, note ? note : c->auth.pwchange_prompt);
  it = ssh_prompt_items(p, 3);
  it[0].text = "Current password: ";
  it[1].text = "New password: ";
  it[2].text = "Confirm new password: ";
  it[0].echo = it[1].echo = it[2].echo = 0;
  ai->may_autofill = 0;
  c->auth.step = SSH_AU_PROMPT;
  ssh_prompt_raise(c, p);
}

static void start_load(sd_ssh_conn *c, sd_secbuf *pass);

/* Reconnect cache: the passphrase that decrypted this identity before. Returns 1 when used. */
static int passphrase_from_cache(sd_ssh_conn *c)
{
  uint32_t idx = cur_cand(c)->ident;
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
  const ssh_cand *k = cur_cand(c);
  const ssh_ident *id = &c->ids[k->ident];
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
  ai->key_fingerprint = ssh_prompt_str(p, k->fp);
  ai->may_autofill = c->auth.pass_tries == 0;   /* passphrases are unaffected by TM-R05 */
  ai->hostkey_just_accepted = 0;
  c->auth.step = SSH_AU_PROMPT;
  ssh_prompt_raise(c, p);
}

/* ---- candidate preparation (worker): read and probe identities, certificates, agents ---- */

enum { CERT_NONE, CERT_USED, CERT_EXPIRED, CERT_MISMATCH, CERT_BAD, CERT_HOST };

typedef struct prep_work {
  ssh_work w;
  const ssh_ident *ids; uint32_t nid;   /* borrowed from the connection config (outlives workers) */
  uint32_t agents; int identities_only;
  /* results */
  ssh_cand *cand; uint32_t ncand;
  sd_secbuf **idfile;
  uint8_t *idenc;
  sd_err *iderr;
  uint8_t *certst;
  sd_err agent_err[2];
  uint32_t agent_count[2];
  sd_err err;
} prep_work;

static sd_err read_file(const wchar_t *path, size_t max, sd_secbuf **out)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  DWORD got = 0;
  sd_err e;
  *out = NULL;
  if (h == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_NOT_FOUND;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || (uint64_t)sz.QuadPart > max) { CloseHandle(h); return SD_E_KEY_FORMAT; }
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

static uint64_t unix_now(void)
{
  FILETIME ft;
  ULARGE_INTEGER u;
  GetSystemTimeAsFileTime(&ft);
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return (u.QuadPart - 116444736000000000ull) / 10000000ull;
}

static int cand_has_blob(const prep_work *pw, const uint8_t *b, size_t n)
{
  uint32_t i;
  for (i = 0; i < pw->ncand; i++)
    if (pw->cand[i].blob_len == n && memcmp(pw->cand[i].blob, b, n) == 0) return 1;
  return 0;
}

/* Adds a candidate (copies the blobs). plain: the plain public key (for fingerprint and type). */
static void add_cand(prep_work *pw, uint8_t src, uint32_t ident, uint32_t agent, const uint8_t *blob, size_t n,
                     const uint8_t *sign_blob, size_t sn, const uint8_t *plain, size_t pn, int is_cert, int pub_unknown)
{
  ssh_cand *k;
  sd_span t;
  if (pw->err != SD_OK || pw->ncand >= AUTH_MAX_CANDS) return;
  if (!pub_unknown && cand_has_blob(pw, blob, n)) return;
  k = &pw->cand[pw->ncand];
  memset(k, 0, sizeof(*k));
  k->src = src;
  k->ident = ident;
  k->agent = agent;
  k->is_cert = (uint8_t)is_cert;
  k->pub_unknown = (uint8_t)pub_unknown;
  if (n) {
    k->blob = (uint8_t *)sd_alloc(n);
    if (!k->blob) { pw->err = SD_E_NO_MEMORY; return; }
    memcpy(k->blob, blob, n);
    k->blob_len = n;
  }
  if (sn) {
    k->sign_blob = (uint8_t *)sd_alloc(sn);
    if (!k->sign_blob) { sd_free(k->blob); pw->err = SD_E_NO_MEMORY; return; }
    memcpy(k->sign_blob, sign_blob, sn);
    k->sign_blob_len = sn;
  }
  if (pn) {
    t = ssh_blob_key_type(plain, pn);
    if (!ssh_span_copy(t, k->key_type, sizeof(k->key_type))) k->key_type[0] = '\0';
    if (ssh_pubblob_info(plain, pn, NULL, &k->bits, NULL) != SD_OK) k->bits = 0;
    if (sd_hostkey_fingerprint_sha256(plain, pn, k->fp) != SD_OK) k->fp[0] = '\0';
  }
  pw->ncand++;
}

/* Plain key of an agent identity (the certified key for certificates). */
static int agent_plain(const sd_agent_identity *id, uint8_t *out, size_t cap, size_t *n, int *is_cert)
{
  char base[48];
  sd_span t = ssh_blob_key_type(id->blob, id->blob_len);
  *is_cert = ssh_cert_type_base(t, base, sizeof(base));
  if (*is_cert) return ssh_cert_plain_pub(id->blob, id->blob_len, out, cap, n) == SD_OK;
  if (id->blob_len > cap) return 0;
  memcpy(out, id->blob, id->blob_len);
  *n = id->blob_len;
  return 1;
}

/* A certificate for a key: user type, valid now, certifying `plain` (when known). */
static int cert_ok(prep_work *pw, uint32_t i, const uint8_t *cert, size_t cl, const uint8_t *plain, size_t pn, uint64_t now)
{
  sd_ssh_cert_info *ci = (sd_ssh_cert_info *)sd_alloc(sizeof(*ci));
  int ok = 0;
  if (!ci) { pw->err = SD_E_NO_MEMORY; return 0; }
  if (sd_ssh_cert_parse(cert, cl, ci) != SD_OK) pw->certst[i] = CERT_BAD;
  else if (ci->cert_type != SD_CERT_USER) pw->certst[i] = CERT_HOST;
  else if (pn && (ci->key_len != pn || memcmp(ci->key_blob, plain, pn) != 0)) pw->certst[i] = CERT_MISMATCH;
  else if (!sd_ssh_cert_valid_at(ci, now)) pw->certst[i] = CERT_EXPIRED;
  else { pw->certst[i] = CERT_USED; ok = 1; }
  sd_free(ci);
  return ok;
}

static void prep_do(ssh_work *w)
{
  prep_work *pw = (prep_work *)w;
  sd_agent_list *lists[2] = { NULL, NULL };
  static const uint32_t kinds[2] = { SD_AGENT_PAGEANT, SD_AGENT_OPENSSH };
  uint64_t now = unix_now();
  uint32_t i, a, j;
  sd_ssh_key_probe_info *info = NULL;
  uint8_t *certbuf = NULL, *plain = NULL;
  const size_t certcap = 32768;

  pw->cand = (ssh_cand *)sd_calloc(AUTH_MAX_CANDS, sizeof(ssh_cand));
  pw->idfile = (sd_secbuf **)sd_calloc(pw->nid ? pw->nid : 1, sizeof(sd_secbuf *));
  pw->idenc = (uint8_t *)sd_calloc(pw->nid ? pw->nid : 1, 1);
  pw->iderr = (sd_err *)sd_calloc(pw->nid ? pw->nid : 1, sizeof(sd_err));
  pw->certst = (uint8_t *)sd_calloc(pw->nid ? pw->nid : 1, 1);
  info = (sd_ssh_key_probe_info *)sd_alloc(sizeof(*info));
  certbuf = (uint8_t *)sd_alloc(certcap);
  plain = (uint8_t *)sd_alloc(1024);
  if (!pw->cand || !pw->idfile || !pw->idenc || !pw->iderr || !pw->certst || !info || !certbuf || !plain) {
    pw->err = SD_E_NO_MEMORY;
    goto out;
  }
  for (a = 0; a < 2; a++) {
    pw->agent_err[a] = SD_E_NOT_FOUND;
    if (pw->agents & kinds[a]) {
      pw->agent_err[a] = sd_agent_list_identities(kinds[a], &lists[a]);
      if (lists[a]) pw->agent_count[a] = lists[a]->count;
    }
  }

  for (i = 0; i < pw->nid && pw->err == SD_OK; i++) {
    const ssh_ident *id = &pw->ids[i];
    sd_secbuf *bytes = NULL, *certfile = NULL;
    size_t cl = 0, pn;
    int have_cert = 0, pub_unknown;
    const sd_agent_identity *holder = NULL;
    if (id->kind == SD_ID_AGENT_KEY) {
      /* certificates first, then the plain key, from every enabled agent */
      int pass;
      for (pass = 0; pass < 2; pass++)
        for (a = 0; a < 2; a++)
          for (j = 0; lists[a] && j < lists[a]->count; j++) {
            const sd_agent_identity *ai = &lists[a]->ids[j];
            char fp[64];
            int isc = 0;
            if (!agent_plain(ai, plain, 1024, &pn, &isc) || isc != (pass == 0)) continue;
            if (sd_hostkey_fingerprint_sha256(plain, pn, fp) != SD_OK || strcmp(fp, id->agent_fp) != 0) continue;
            add_cand(pw, SSH_CS_AGENT, i, kinds[a], ai->blob, ai->blob_len, ai->blob, ai->blob_len, plain, pn, isc, 0);
          }
      continue;
    }
    if (id->kind == SD_ID_FILE) pw->iderr[i] = read_file(id->path, SSH_KEY_MAX_FILE, &bytes);
    else pw->iderr[i] = sd_secbuf_from(id->blob->p, id->blob->len, &bytes);
    if (pw->iderr[i] != SD_OK) continue;
    pw->iderr[i] = sd_ssh_key_probe(bytes->p, bytes->len, info);
    if (pw->iderr[i] != SD_OK) { sd_secbuf_free(bytes); continue; }
    pw->idfile[i] = bytes;
    pw->idenc[i] = (uint8_t)info->encrypted;
    pub_unknown = info->pub_len == 0;
    /* certificate: explicit bytes, explicit file, or <path>-cert.pub */
    if (id->cert_blob) {
      have_cert = sd_ssh_pubkey_parse(id->cert_blob, id->cert_len, certbuf, certcap, &cl, NULL, 0) == SD_OK;
      if (!have_cert) pw->certst[i] = CERT_BAD;
    } else {
      wchar_t cpath[MAX_PATH + 16];
      const wchar_t *cp = id->cert_path;
      if (!cp && id->kind == SD_ID_FILE && wcslen(id->path) + 10 < SD_COUNTOF(cpath)) {
        _snwprintf_s(cpath, SD_COUNTOF(cpath), _TRUNCATE, L"%s-cert.pub", id->path);
        cp = cpath;
      }
      if (cp && read_file(cp, 256u * 1024u, &certfile) == SD_OK) {
        have_cert = sd_ssh_pubkey_parse(certfile->p, certfile->len, certbuf, certcap, &cl, NULL, 0) == SD_OK;
        if (!have_cert) pw->certst[i] = CERT_BAD;
        sd_secbuf_free(certfile);
      } else if (id->cert_path) {
        pw->certst[i] = CERT_BAD;
      }
    }
    if (have_cert && !cert_ok(pw, i, certbuf, cl, info->pub_blob, info->pub_len, now)) have_cert = 0;
    /* an enabled agent holding this key signs for it (no passphrase) */
    for (a = 0; a < 2 && !holder && !pub_unknown; a++)
      for (j = 0; lists[a] && j < lists[a]->count; j++)
        if (lists[a]->ids[j].blob_len == info->pub_len && memcmp(lists[a]->ids[j].blob, info->pub_blob, info->pub_len) == 0) {
          holder = &lists[a]->ids[j];
          break;
        }
    if (have_cert) {
      if (holder)
        add_cand(pw, SSH_CS_AGENT, i, holder->agent, certbuf, cl, holder->blob, holder->blob_len, info->pub_blob,
                 info->pub_len, 1, 0);
      else
        add_cand(pw, SSH_CS_KEY, i, 0, certbuf, cl, NULL, 0, info->pub_blob, info->pub_len, 1, pub_unknown);
    }
    if (holder)
      add_cand(pw, SSH_CS_AGENT, i, holder->agent, info->pub_blob, info->pub_len, holder->blob, holder->blob_len,
               info->pub_blob, info->pub_len, 0, 0);
    else
      add_cand(pw, SSH_CS_KEY, i, 0, info->pub_blob, info->pub_len, NULL, 0, info->pub_blob, info->pub_len, 0, pub_unknown);
  }

  /* remaining agent keys: Pageant first, then the OpenSSH agent (01 §6.2 step 2) */
  if (!pw->identities_only)
    for (a = 0; a < 2; a++)
      for (j = 0; lists[a] && j < lists[a]->count; j++) {
        const sd_agent_identity *ai = &lists[a]->ids[j];
        size_t pn = 0;
        int isc = 0;
        if (!agent_plain(ai, plain, 1024, &pn, &isc)) continue;
        add_cand(pw, SSH_CS_AGENT, AUTH_NO_IDENT, kinds[a], ai->blob, ai->blob_len, ai->blob, ai->blob_len, plain, pn,
                 isc, 0);
      }

out:
  for (a = 0; a < 2; a++) sd_agent_list_free(lists[a]);
  sd_free(info);
  sd_free(certbuf);
  sd_free(plain);
}

static void prep_free(prep_work *pw)
{
  uint32_t i;
  if (pw->cand) {
    for (i = 0; i < pw->ncand; i++) {
      sd_free(pw->cand[i].blob);
      sd_free(pw->cand[i].sign_blob);
    }
    sd_free(pw->cand);
  }
  if (pw->idfile) {
    for (i = 0; i < pw->nid; i++) sd_secbuf_free(pw->idfile[i]);
    sd_free(pw->idfile);
  }
  sd_free(pw->idenc);
  sd_free(pw->iderr);
  sd_free(pw->certst);
  sd_free(pw);
}

static void prep_drop(ssh_cmd *cmd) { prep_free((prep_work *)cmd); }

static const char *cert_note(uint8_t st)
{
  switch (st) {
  case CERT_EXPIRED: return "expired or not yet valid";
  case CERT_MISMATCH: return "certifies another key";
  case CERT_HOST: return "is a host certificate";
  case CERT_BAD: return "unreadable";
  default: return "";
  }
}

static void prep_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  prep_work *pw = (prep_work *)cmd;
  ssh_auth *a = &c->auth;
  uint32_t i;
  if (pw->w.gen != c->gen || c->failing || c->st != SSH_ST_AUTH || a->step != SSH_AU_PK_PREP) { prep_free(pw); return; }
  if (pw->err != SD_OK) { sd_err e = pw->err; prep_free(pw); ssh_fail(c, e, SSH_DISCONNECT_BY_APPLICATION, "auth"); return; }
  for (i = 0; i < 2; i++) {
    uint32_t kind = i ? SD_AGENT_OPENSSH : SD_AGENT_PAGEANT;
    if (!(c->agents & kind)) continue;
    if (pw->agent_err[i] == SD_OK)
      ssh_log(c, SD_LOG_DEBUG, "%s agent: %u identities", i ? "openssh" : "pageant", pw->agent_count[i]);
    else
      ssh_log(c, SD_LOG_INFO, "%s agent unavailable: %s", i ? "openssh" : "pageant", sd_err_name(pw->agent_err[i]));
  }
  for (i = 0; i < pw->nid; i++) {
    if (c->ids[i].kind != SD_ID_AGENT_KEY && pw->iderr[i] != SD_OK)
      ssh_log(c, SD_LOG_WARN, "identity %u skipped: %s", i + 1, sd_err_name(pw->iderr[i]));
    if (pw->certst[i] != CERT_NONE && pw->certst[i] != CERT_USED)
      ssh_log(c, SD_LOG_WARN, "certificate of identity %u skipped: %s", i + 1, cert_note(pw->certst[i]));
  }
  a->cand = pw->cand;
  a->ncand = pw->ncand;
  a->idfile = pw->idfile;
  a->idenc = pw->idenc;
  a->nid = pw->nid;
  pw->cand = NULL;
  pw->ncand = 0;
  pw->idfile = NULL;
  pw->idenc = NULL;
  a->idkey = (sd_ssh_key **)sd_calloc(a->nid ? a->nid : 1, sizeof(sd_ssh_key *));
  prep_free(pw);
  if (!a->idkey) { ssh_fail(c, SD_E_NO_MEMORY, SSH_DISCONNECT_BY_APPLICATION, "auth"); return; }
  a->prep_done = 1;
  ssh_log(c, SD_LOG_DEBUG, "publickey: %u candidates", a->ncand);
  auth_next(c);
}

static void start_prep(sd_ssh_conn *c)
{
  prep_work *pw = (prep_work *)sd_calloc(1, sizeof(*pw));
  if (!pw) { ssh_fail(c, SD_E_NO_MEMORY, 0, "auth"); return; }
  pw->ids = c->ids;
  pw->nid = c->id_count;
  pw->agents = c->agents;
  pw->identities_only = c->identities_only;
  pw->w.cmd.run = prep_done;
  pw->w.cmd.drop = prep_drop;
  pw->w.work = prep_do;
  c->auth.step = SSH_AU_PK_PREP;
  if (ssh_queue_work(c, &pw->w) != SD_OK) { prep_free(pw); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
}

/* ---- algorithm choice (01 §4.5, RFC 8332) ---- */

static int server_is_openssh_72(const sd_ssh_conn *c)
{
  const char *v = strstr(c->server_version, "OpenSSH_");
  unsigned maj = 0, min = 0;
  if (!v) return 0;
  v += 8;
  while (*v >= '0' && *v <= '9') maj = maj * 10u + (unsigned)(*v++ - '0');
  if (*v == '.') {
    v++;
    while (*v >= '0' && *v <= '9') min = min * 10u + (unsigned)(*v++ - '0');
  }
  return maj > 7 || (maj == 7 && min >= 2);
}

static void choose_rsa_algs(sd_ssh_conn *c)
{
  ssh_auth *a = &c->auth;
  static const char *const k_sha2[2] = { "rsa-sha2-512", "rsa-sha2-256" };
  uint32_t i;
  a->rsa_nalg = 0;
  a->rsa_idx = 0;
  if (c->server_sig_algs[0]) {
    for (i = 0; i < 2; i++)
      if (ssh_csv_contains(c->server_sig_algs, k_sha2[i])) a->rsa_algs[a->rsa_nalg++] = k_sha2[i];
    if (!a->rsa_nalg) a->rsa_algs[a->rsa_nalg++] = "ssh-rsa";
    return;
  }
  if (server_is_openssh_72(c)) {
    a->rsa_algs[0] = "rsa-sha2-512"; a->rsa_algs[1] = "rsa-sha2-256"; a->rsa_algs[2] = "ssh-rsa";
  } else {
    a->rsa_algs[0] = "ssh-rsa"; a->rsa_algs[1] = "rsa-sha2-512"; a->rsa_algs[2] = "rsa-sha2-256";
  }
  a->rsa_nalg = 3;
}

/* Algorithm name for the current attempt of k. */
static void cand_alg(sd_ssh_conn *c, const ssh_cand *k, char *out, size_t cap)
{
  if (!strcmp(k->key_type, "ssh-rsa")) {
    const char *base = c->auth.rsa_algs[c->auth.rsa_idx];
    if (k->is_cert) _snprintf_s(out, cap, _TRUNCATE, "%s-cert-v01@openssh.com", base);
    else _snprintf_s(out, cap, _TRUNCATE, "%s", base);
    return;
  }
  if (k->is_cert || !k->key_type[0]) {
    sd_span t = ssh_blob_key_type(k->blob, k->blob_len);
    if (!ssh_span_copy(t, out, cap)) out[0] = '\0';
    return;
  }
  _snprintf_s(out, cap, _TRUNCATE, "%s", k->key_type);
}

static void send_pk(sd_ssh_conn *c, const uint8_t *sig, size_t sig_len)
{
  const ssh_cand *k = cur_cand(c);
  sd_wr w;
  sd_wr_init(&w, 64 * 1024);
  write_req_head(c, &w, "publickey");
  sd_wr_bool(&w, sig != NULL);
  sd_wr_cstring(&w, c->auth.alg);
  sd_wr_string(&w, k->blob, k->blob_len);
  if (sig) sd_wr_string(&w, sig, sig_len);
  ssh_send_wr(c, &w);
}

static void send_query(sd_ssh_conn *c)
{
  const ssh_cand *k = cur_cand(c);
  cand_alg(c, k, c->auth.alg, sizeof(c->auth.alg));
  c->auth.pk_attempts++;
  c->auth.step = SSH_AU_PK_QUERY;
  ssh_log(c, SD_LOG_DEBUG, "offering %s %s%s (%s)", c->auth.alg, k->fp, k->is_cert ? " certificate" : "",
          k->src == SSH_CS_AGENT ? (k->agent == SD_AGENT_PAGEANT ? "pageant" : "openssh agent") : "key");
  send_pk(c, NULL, 0);
}

/* ---- key loading (worker) ---- */

typedef struct key_work {
  ssh_work w;
  sd_secbuf *bytes;           /* copy of the key file */
  sd_secbuf *pass;            /* passphrase or NULL */
  sd_ssh_key *key;
  sd_err err;
} key_work;

static void key_do(ssh_work *w)
{
  key_work *k = (key_work *)w;
  k->err = sd_ssh_key_load(k->bytes->p, k->bytes->len, k->pass ? (const char *)k->pass->p : NULL,
                           k->pass ? k->pass->len : 0, &k->key);
}

static void key_free(key_work *k)
{
  sd_secbuf_free(k->bytes);
  sd_secbuf_free(k->pass);
  sd_ssh_key_free(k->key);
  sd_free(k);
}

static void key_drop(ssh_cmd *cmd) { key_free((key_work *)cmd); }

/* After the key of a pub_unknown candidate is known: fill in the blob, check the certificate. */
static int complete_unknown(sd_ssh_conn *c, ssh_cand *k, const sd_ssh_key *key)
{
  size_t pl;
  const uint8_t *pub = sd_ssh_key_public_blob(key, &pl);
  if (k->is_cert) {
    uint8_t plain[1024];
    size_t pn = 0;
    if (ssh_cert_plain_pub(k->blob, k->blob_len, plain, sizeof(plain), &pn) != SD_OK || pn != pl ||
        memcmp(plain, pub, pl) != 0) {
      ssh_log(c, SD_LOG_WARN, "certificate of identity %u certifies another key", k->ident + 1);
      return 0;
    }
  } else {
    k->blob = (uint8_t *)sd_alloc(pl);
    if (!k->blob) return 0;
    memcpy(k->blob, pub, pl);
    k->blob_len = pl;
  }
  if (!ssh_span_copy(ssh_blob_key_type(pub, pl), k->key_type, sizeof(k->key_type))) k->key_type[0] = '\0';
  k->bits = sd_ssh_key_bits(key);
  if (sd_hostkey_fingerprint_sha256(pub, pl, k->fp) != SD_OK) k->fp[0] = '\0';
  k->pub_unknown = 0;
  return 1;
}

static void key_ready(sd_ssh_conn *c)
{
  ssh_cand *k = cur_cand(c);
  if (k->pub_unknown) {
    if (!complete_unknown(c, k, c->auth.idkey[k->ident])) { auth_next(c); return; }
    if (!strcmp(k->key_type, "ssh-rsa")) choose_rsa_algs(c);
    if (c->auth.pk_attempts >= AUTH_MAX_PK_ATTEMPTS) { auth_next(c); return; }
    send_query(c);
    return;
  }
  start_sign(c);
}

static void load_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  key_work *k = (key_work *)cmd;
  ssh_auth *a = &c->auth;
  uint32_t idx;
  if (k->w.gen != c->gen || c->failing || c->st != SSH_ST_AUTH || a->step != SSH_AU_PK_LOAD) { key_free(k); return; }
  idx = cur_cand(c)->ident;
  if (a->pp_from_cache) {
    a->pp_from_cache = 0;
    if (k->err == SD_E_BAD_PASSPHRASE) {    /* stale cache entry: drop it, ask normally (not a try) */
      if (idx < c->cache.npass) ssh_secret_clear(&c->cache.pass[idx]);
      key_free(k);
      prompt_passphrase(c);
      return;
    }
  }
  if (k->err == SD_OK && a->pp_pending) {
    if (ssh_cache_usable(c) && idx < c->cache.npass &&
        ssh_secret_store(&c->cache.pass[idx], a->pp_pending->p, a->pp_pending->len) != SD_OK)
      ssh_log(c, SD_LOG_WARN, "reconnect cache unavailable; the passphrase is not kept");
  }
  sd_secbuf_free(a->pp_pending);
  a->pp_pending = NULL;
  if (k->err == SD_E_BAD_PASSPHRASE && ++a->pass_tries < AUTH_MAX_PASS_TRIES) {
    key_free(k);
    prompt_passphrase(c);
    return;
  }
  if (k->err != SD_OK) {
    ssh_log(c, SD_LOG_WARN, "identity %u unusable: %s", idx + 1, sd_err_name(k->err));
    key_free(k);
    auth_next(c);
    return;
  }
  sd_ssh_key_free(a->idkey[idx]);
  a->idkey[idx] = k->key;
  k->key = NULL;
  key_free(k);
  key_ready(c);
}

static void start_load(sd_ssh_conn *c, sd_secbuf *pass)
{
  const ssh_cand *kc = cur_cand(c);
  key_work *k = (key_work *)sd_calloc(1, sizeof(*k));
  sd_secbuf *src = c->auth.idfile[kc->ident];
  sd_err e;
  if (!k) { sd_secbuf_free(pass); ssh_fail(c, SD_E_NO_MEMORY, 0, "auth"); return; }
  k->pass = pass;
  e = sd_secbuf_from(src->p, src->len, &k->bytes);
  if (e != SD_OK) { k->bytes = NULL; key_free(k); ssh_fail(c, e, 0, "auth"); return; }
  k->w.cmd.run = load_done;
  k->w.cmd.drop = key_drop;
  k->w.work = key_do;
  c->auth.step = SSH_AU_PK_LOAD;
  if (ssh_queue_work(c, &k->w) != SD_OK) { key_free(k); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
}

/* The key of the current candidate: loaded already, needs a passphrase, or loads without one. */
static void obtain_key(sd_ssh_conn *c)
{
  const ssh_cand *k = cur_cand(c);
  if (c->auth.idkey[k->ident]) { key_ready(c); return; }
  c->auth.pass_tries = 0;
  c->auth.pp_cache_tried = 0;
  if (c->auth.idenc[k->ident]) prompt_passphrase(c);
  else start_load(c, NULL);
}

/* ---- signing (worker: RSA can take a while, agents may wait for a confirmation) ---- */

typedef struct sign_work {
  ssh_work w;
  sd_ssh_key *key;            /* owned while the worker runs (SSH_CS_KEY) */
  uint32_t ident;
  uint32_t agent;             /* SSH_CS_AGENT */
  uint8_t *agent_blob; size_t agent_blob_len;
  uint32_t flags;
  char alg[64];
  sd_secbuf *data;
  uint8_t *sig; size_t sig_len;
  sd_err err;
} sign_work;

static void sign_do(ssh_work *w)
{
  sign_work *s = (sign_work *)w;
  if (s->key) {
    size_t cap = 64u + 2u * 2048u + 64u;
    s->sig = (uint8_t *)sd_alloc(cap);
    if (!s->sig) { s->err = SD_E_NO_MEMORY; return; }
    s->err = sd_ssh_key_sign_alg(s->key, s->alg, s->data->p, s->data->len, s->sig, cap, &s->sig_len);
  } else {
    s->err = sd_agent_sign(s->agent, s->agent_blob, s->agent_blob_len, s->data->p, s->data->len, s->flags, &s->sig,
                           &s->sig_len);
  }
}

static void sign_free(sign_work *s)
{
  sd_ssh_key_free(s->key);
  sd_free(s->agent_blob);
  sd_secbuf_free(s->data);
  sd_free(s->sig);
  sd_free(s);
}

static void sign_drop(ssh_cmd *cmd) { sign_free((sign_work *)cmd); }

/* The signature's algorithm must be the one we asked for (a wrong agent answer fails early); agent
   keys of types we do not know (sk-*, other @ names) are forwarded unchecked. */
static int sig_alg_ok(const char *alg, const uint8_t *sig, size_t n)
{
  char base[64];
  sd_span t = ssh_blob_key_type(sig, n);
  const char *suffix = strstr(alg, "-cert-v01@openssh.com");
  size_t bl = suffix ? (size_t)(suffix - alg) : strlen(alg);
  if (!t.n || bl >= sizeof(base)) return 0;
  memcpy(base, alg, bl);
  base[bl] = '\0';
  if (ssh_span_eq(t, base)) return 1;
  return strncmp(base, "sk-", 3) == 0 || strchr(base, '@') != NULL;
}

static void sign_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  sign_work *s = (sign_work *)cmd;
  ssh_auth *a = &c->auth;
  const ssh_cand *k;
  if (s->w.gen != c->gen || c->failing || c->st != SSH_ST_AUTH || a->step != SSH_AU_PK_SIGNING) { sign_free(s); return; }
  k = cur_cand(c);
  if (s->key) {           /* hand the key back for later candidates of the same identity */
    a->idkey[s->ident] = s->key;
    s->key = NULL;
  }
  if (s->err == SD_OK && !sig_alg_ok(a->alg, s->sig, s->sig_len)) s->err = SD_E_PROTOCOL;
  if (s->err != SD_OK) {
    ssh_log(c, SD_LOG_WARN, "signing with %s failed: %s", k->fp, sd_err_name(s->err));
    sign_free(s);
    auth_next(c);
    return;
  }
  if (!strcmp(a->alg, "ssh-rsa") || !strcmp(a->alg, "ssh-rsa-cert-v01@openssh.com")) c->legacy_mask |= SD_LEGACY_USERAUTH_SHA1;
  if (!strcmp(k->key_type, "ssh-rsa") && k->bits && k->bits < 2048) c->legacy_mask |= SD_LEGACY_RSA_SHORT;
  a->step = SSH_AU_PK_SIGN;
  send_pk(c, s->sig, s->sig_len);
  sign_free(s);
}

static void start_sign(sd_ssh_conn *c)
{
  ssh_auth *a = &c->auth;
  const ssh_cand *k = cur_cand(c);
  sign_work *s = (sign_work *)sd_calloc(1, sizeof(*s));
  sd_wr d;
  sd_err e;
  if (!s) { ssh_fail(c, SD_E_NO_MEMORY, 0, "auth"); return; }
  sd_wr_init_secret(&d, 128 * 1024);
  sd_wr_string(&d, c->session_id, c->session_id_len);
  write_req_head(c, &d, "publickey");
  sd_wr_bool(&d, 1);
  sd_wr_cstring(&d, a->alg);
  sd_wr_string(&d, k->blob, k->blob_len);
  e = sd_wr_ok(&d) ? sd_secbuf_from(d.p, d.len, &s->data) : SD_E_NO_MEMORY;
  sd_wr_free(&d);
  if (e != SD_OK) { s->data = NULL; sign_free(s); ssh_fail(c, e, 0, "auth"); return; }
  memcpy(s->alg, a->alg, sizeof(s->alg));
  if (k->src == SSH_CS_AGENT) {
    s->agent = k->agent;
    s->agent_blob = (uint8_t *)sd_alloc(k->sign_blob_len);
    if (!s->agent_blob) { sign_free(s); ssh_fail(c, SD_E_NO_MEMORY, 0, "auth"); return; }
    memcpy(s->agent_blob, k->sign_blob, k->sign_blob_len);
    s->agent_blob_len = k->sign_blob_len;
    if (strncmp(a->alg, "rsa-sha2-256", 12) == 0) s->flags = SD_AGENT_SIGN_RSA_SHA2_256;
    else if (strncmp(a->alg, "rsa-sha2-512", 12) == 0) s->flags = SD_AGENT_SIGN_RSA_SHA2_512;
  } else {
    s->ident = k->ident;
    s->key = a->idkey[k->ident];
    a->idkey[k->ident] = NULL;
  }
  s->w.cmd.run = sign_done;
  s->w.cmd.drop = sign_drop;
  s->w.work = sign_do;
  a->step = SSH_AU_PK_SIGNING;
  if (ssh_queue_work(c, &s->w) != SD_OK) {
    if (s->key) { a->idkey[s->ident] = s->key; s->key = NULL; }
    sign_free(s);
    ssh_fail(c, SD_E_INTERNAL, 0, "worker");
  }
}

static void start_candidate(sd_ssh_conn *c)
{
  ssh_cand *k = &c->auth.cand[c->auth.cand_next++];
  c->auth.rsa_nalg = 1;
  c->auth.rsa_idx = 0;
  c->auth.rsa_algs[0] = NULL;
  if (!strcmp(k->key_type, "ssh-rsa")) choose_rsa_algs(c);
  if (k->pub_unknown) { obtain_key(c); return; }   /* the query needs the public key */
  send_query(c);
}

/* ---- method selection (01 §6.1) ---- */

static void auth_next(sd_ssh_conn *c)
{
  ssh_auth *a = &c->auth;
  if (c->failing) return;
  if ((c->methods & SD_AUTH_PUBLICKEY) && server_allows(c, "publickey") && !a->partial_pk &&
      a->pk_attempts < AUTH_MAX_PK_ATTEMPTS && (c->id_count || c->agents)) {
    if (!a->prep_done) { start_prep(c); return; }
    if (a->cand_next < a->ncand) { start_candidate(c); return; }
  }
  if (a->prep_done) pk_release(a);
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
    if (a->pk_attempts >= AUTH_MAX_PK_ATTEMPTS)
      ssh_log(c, SD_LOG_WARN, "publickey: attempt limit reached (identities_only limits the keys offered)");
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

/* RSA: a refused algorithm is retried with the next one (01 §4.5). Returns 1 when a new query went out. */
static int rsa_retry(sd_ssh_conn *c)
{
  ssh_auth *a = &c->auth;
  if (!a->cand_next || strcmp(cur_cand(c)->key_type, "ssh-rsa") != 0) return 0;
  if (a->rsa_idx + 1 >= a->rsa_nalg || a->pk_attempts >= AUTH_MAX_PK_ATTEMPTS) return 0;
  a->rsa_idx++;
  send_query(c);
  return 1;
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
  case SSH_AU_PK_QUERY:
    if (rsa_retry(c)) return;
    break;
  case SSH_AU_PK_SIGN:
    if (partial) { a->partial_pk = 1; c->methods_used |= SD_AUTH_PUBLICKEY; break; }
    if (rsa_retry(c)) return;
    break;
  case SSH_AU_PASSWORD:
  case SSH_AU_PWCHANGE:
    if (partial) { a->partial_pw = 1; c->methods_used |= SD_AUTH_PASSWORD; store_password(c); }
    else if (a->pw_from_cache) {   /* the cached password no longer works: drop it, prompt (not a round) */
      ssh_log(c, SD_LOG_INFO, "cached password rejected; dropped from the reconnect cache");
      ssh_secret_clear(&c->cache.password);
    } else a->password_rounds++;
    if (a->step == SSH_AU_PWCHANGE && !partial) ssh_log(c, SD_LOG_WARN, "password change refused by the server");
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
  if (!sd_rd_done(&r)) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad INFO_REQUEST"); return; }
  if (np == 0) {   /* "press enter" rounds are answered at once (01 §6.4) */
    uint8_t b[8];
    if (++c->auth.kbd_empty_rounds > AUTH_MAX_INFO_ROUNDS) {
      ssh_fail(c, SD_E_AUTH_FAILED, SSH_DISCONNECT_BY_APPLICATION, "too many keyboard-interactive rounds");
      return;
    }
    b[0] = SSH_MSG_USERAUTH_INFO_RESPONSE;
    sd_store_be32(b + 1, 0);
    ssh_send(c, b, 5);
    return;
  }
  if (c->auth.kbd_info_rounds >= AUTH_MAX_INFO_ROUNDS) {
    ssh_fail(c, SD_E_AUTH_FAILED, SSH_DISCONNECT_BY_APPLICATION, "too many keyboard-interactive rounds");
    return;
  }
  {
    /* round counts the prompt rounds of this connection: the second one (e.g. the OTP after the
       password) has round 1 and never auto-fills */
    uint32_t round = c->auth.kbd_info_rounds++;
    sd_prompt *pr = new_auth_prompt(c, SSH_PP_KBDINT, SD_PROMPT_KBDINT, round);
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
    ai->may_autofill = np == 1 && !echo[0] && round == 0 && !c->hostkey_just_accepted;
    c->auth.step = SSH_AU_PROMPT;
    ssh_prompt_raise(c, pr);
  }
}

static void on_passwd_changereq(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  sd_rd r;
  sd_span prompt;
  sd_rd_init(&r, p + 1, n - 1);
  prompt = sd_rd_string(&r, 4096);
  (void)sd_rd_string(&r, 256);   /* language */
  if (!sd_rd_done(&r)) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad PASSWD_CHANGEREQ"); return; }
  /* the password just sent was right but has expired: it is not cached (it no longer works) */
  sd_secbuf_free(c->auth.pw_pending);
  c->auth.pw_pending = NULL;
  if (c->auth.pw_from_cache) ssh_secret_clear(&c->cache.password);
  c->auth.pw_from_cache = 0;
  if (c->auth.pwchange_rounds >= AUTH_MAX_ROUNDS) {
    ssh_log(c, SD_LOG_WARN, "password change: too many rounds");
    c->auth.password_rounds = AUTH_MAX_ROUNDS;
    auth_next(c);
    return;
  }
  ssh_sanitize(prompt.p, prompt.n, c->auth.pwchange_prompt, sizeof(c->auth.pwchange_prompt));
  ssh_log(c, SD_LOG_INFO, "server requests a password change");
  prompt_new_password(c, NULL);
}

void ssh_auth_on_msg(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  uint8_t m = p[0];
  switch (m) {
  case SSH_MSG_USERAUTH_SUCCESS:
    if (c->auth.step == SSH_AU_PK_SIGN) c->methods_used |= SD_AUTH_PUBLICKEY;
    else if (c->auth.step == SSH_AU_PASSWORD || c->auth.step == SSH_AU_PWCHANGE) {
      c->methods_used |= SD_AUTH_PASSWORD;
      store_password(c);
    } else if (c->auth.step == SSH_AU_KBDINT) c->methods_used |= SD_AUTH_KBDINT;
    pk_release(&c->auth);
    ssh_on_authenticated(c);
    return;
  case SSH_MSG_USERAUTH_FAILURE:
    if (c->auth.step == SSH_AU_PK_PREP || c->auth.step == SSH_AU_PK_LOAD || c->auth.step == SSH_AU_PK_SIGNING ||
        c->auth.step == SSH_AU_PROMPT)
      break;   /* nothing of ours is outstanding */
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
    if (c->cb.on_banner) c->cb.on_banner(c->cb.ctx, c->hop_index, buf);
    sd_free(buf);
    return;
  }
  case 60:
    if (c->auth.step == SSH_AU_PK_QUERY) {        /* PK_OK: string alg, string blob */
      sd_rd r;
      sd_span alg, blob;
      const ssh_cand *k = cur_cand(c);
      sd_rd_init(&r, p + 1, n - 1);
      alg = sd_rd_string(&r, 64);
      blob = sd_rd_string(&r, 64 * 1024);
      if (!sd_rd_done(&r) || !ssh_span_eq(alg, c->auth.alg) || blob.n != k->blob_len ||
          memcmp(blob.p, k->blob, blob.n) != 0) {
        ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "PK_OK for another key");
        return;
      }
      if (k->src == SSH_CS_AGENT) start_sign(c);
      else obtain_key(c);
      return;
    }
    if (c->auth.step == SSH_AU_KBDINT) { on_info_request(c, p, n); return; }
    if (c->auth.step == SSH_AU_PASSWORD || c->auth.step == SSH_AU_PWCHANGE) { on_passwd_changereq(c, p, n); return; }
    break;
  default:
    break;
  }
  ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "unexpected userauth message");
}

static void send_password_change(sd_ssh_conn *c, const sd_secbuf *old_pw, const sd_secbuf *new_pw)
{
  sd_wr w;
  sd_wr_init_secret(&w, 16384);
  write_req_head(c, &w, "password");
  sd_wr_bool(&w, 1);
  sd_wr_string(&w, old_pw->p, old_pw->len);
  sd_wr_string(&w, new_pw->p, new_pw->len);
  c->auth.step = SSH_AU_PWCHANGE;
  ssh_send_wr(c, &w);
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
  if (pp == SSH_PP_PASSWORD && a->n == 3) {   /* SD_PROMPT_NEW_PASSWORD: current, new, confirm */
    if (a->resp[1]->len != a->resp[2]->len || memcmp(a->resp[1]->p, a->resp[2]->p, a->resp[1]->len) != 0) {
      if (++c->auth.pwchange_rounds >= AUTH_MAX_ROUNDS) {
        ssh_fail(c, SD_E_AUTH_FAILED, SSH_DISCONNECT_BY_APPLICATION, "new passwords do not match");
        return;
      }
      prompt_new_password(c, "The new passwords do not match.");
      return;
    }
    c->auth.pwchange_rounds++;
    sd_secbuf_free(c->auth.pw_pending);
    c->auth.pw_pending = NULL;
    if (ssh_cache_usable(c) && sd_secbuf_from(a->resp[1]->p, a->resp[1]->len, &c->auth.pw_pending) != SD_OK)
      c->auth.pw_pending = NULL;
    c->auth.pw_from_cache = 0;
    send_password_change(c, a->resp[0], a->resp[1]);
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
