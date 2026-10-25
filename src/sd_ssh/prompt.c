/* sd_prompt objects (01 §6.7; TM-R05).
 *
 * Lifetime: two references. sd_ssh holds one until the connection is done with the prompt (answer
 * processed, or withdrawn); the host holds one until it answers or cancels (exactly once). The link
 * to the connection is cleared under g_plock at withdrawal, before the connection can be freed, so
 * a late answer finds conn == NULL and returns SD_E_CANCELLED. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "conn_internal.h"

struct sd_prompt {
  volatile LONG refs;
  sd_ssh_conn *conn;           /* guarded by g_plock */
  int answered;                /* guarded by g_plock */
  ssh_prompt_purpose purpose;
  sd_prompt_kind kind;
  sd_auth_prompt_info ainfo;
  sd_hostkey_prompt_info hinfo;
  sd_prompt_item items[16];
  uint32_t nitems;
  char *strs[40];
  uint32_t nstrs;
  ssh_prompt_answer ans;
};

typedef struct prompt_cmd { ssh_cmd cmd; sd_prompt *p; } prompt_cmd;

static sd_once g_plock_once = SD_ONCE_INIT;
static sd_mutex g_plock;

static void plock_init(void *arg) { SD_UNUSED(arg); sd_mutex_init(&g_plock); }
static void plock(void) { sd_once_run(&g_plock_once, plock_init, NULL); sd_mutex_lock(&g_plock); }
static void punlock(void) { sd_mutex_unlock(&g_plock); }

static void prompt_release(sd_prompt *p)
{
  uint32_t i;
  if (InterlockedDecrement(&p->refs) != 0) return;
  for (i = 0; i < p->nstrs; i++) sd_free(p->strs[i]);
  for (i = 0; i < p->ans.n; i++) sd_secbuf_free(p->ans.resp[i]);
  sd_free(p);
}

sd_prompt *ssh_prompt_new(sd_ssh_conn *c, ssh_prompt_purpose purpose, sd_prompt_kind kind)
{
  sd_prompt *p = (sd_prompt *)sd_calloc(1, sizeof(*p));
  if (!p) return NULL;
  p->refs = 2;
  p->conn = c;
  p->purpose = purpose;
  p->kind = kind;
  p->ainfo.kind = kind;
  p->ainfo.name = p->ainfo.instruction = "";
  p->ainfo.host = c->host_utf8;
  p->ainfo.user = c->user;
  p->ainfo.hostkey_just_accepted = c->hostkey_just_accepted;
  p->ainfo.is_pool_member = c->pool_member;
  p->ainfo.is_reconnect = c->is_reconnect;
  p->hinfo.is_reconnect = c->is_reconnect;
  return p;
}

const char *ssh_prompt_str(sd_prompt *p, const char *s)
{
  size_t n;
  char *d;
  if (!s) return NULL;
  if (p->nstrs >= SD_COUNTOF(p->strs)) return "";
  n = strlen(s);
  d = (char *)sd_alloc(n + 1);
  if (!d) return "";
  memcpy(d, s, n + 1);
  p->strs[p->nstrs++] = d;
  return d;
}

sd_auth_prompt_info *ssh_prompt_auth_info(sd_prompt *p) { return &p->ainfo; }
sd_hostkey_prompt_info *ssh_prompt_hk_info(sd_prompt *p) { return &p->hinfo; }

sd_prompt_item *ssh_prompt_items(sd_prompt *p, uint32_t n)
{
  if (n > SD_COUNTOF(p->items)) return NULL;
  p->nitems = n;
  p->ainfo.items = p->items;
  p->ainfo.item_count = n;
  return p->items;
}

ssh_prompt_purpose ssh_prompt_purpose_of(const sd_prompt *p) { return p->purpose; }
ssh_prompt_answer *ssh_prompt_take_answer(sd_prompt *p) { return &p->ans; }

void ssh_prompt_raise(sd_ssh_conn *c, sd_prompt *p)
{
  c->cur_prompt = p;
  if (!c->cb.on_prompt) {
    /* No UI: behave like an immediate cancel. */
    sd_prompt_cancel(p);
    return;
  }
  if (p->kind == SD_PROMPT_HOSTKEY) c->cb.on_prompt(c->cb.ctx, p, NULL, &p->hinfo);
  else c->cb.on_prompt(c->cb.ctx, p, &p->ainfo, NULL);
}

void ssh_prompt_withdraw(sd_ssh_conn *c, sd_prompt *p)
{
  int answered;
  plock();
  answered = p->answered;
  p->conn = NULL;
  punlock();
  if (c->cur_prompt == p) c->cur_prompt = NULL;
  if (!answered && c->cb.on_prompt_withdrawn) c->cb.on_prompt_withdrawn(c->cb.ctx, p);
  prompt_release(p);
}

void ssh_prompt_finish(sd_prompt *p)
{
  plock();
  p->conn = NULL;
  punlock();
  prompt_release(p);
}

static void prompt_cmd_run(sd_ssh_conn *c, ssh_cmd *cmd)
{
  prompt_cmd *pc = (prompt_cmd *)cmd;
  sd_prompt *p = pc->p;
  sd_free(pc);
  if (c->cur_prompt == p) {
    c->cur_prompt = NULL;
    ssh_on_prompt_answered(c, p);   /* consumes the answer */
    ssh_prompt_finish(p);           /* sd_ssh's reference */
  }
  prompt_release(p);                /* the host's reference */
}

static void prompt_cmd_drop(ssh_cmd *cmd)
{
  prompt_cmd *pc = (prompt_cmd *)cmd;
  prompt_release(pc->p);
  sd_free(pc);
}

/* Common answer path. fill() runs under g_plock after validation. */
static sd_err answer(sd_prompt *p, int cancel, sd_hostkey_decision d, int ack, uint32_t n,
                     const char *const *resp, uint32_t flags, int want_kind)
{
  prompt_cmd *pc;
  uint32_t i;
  sd_err e;
  if (!p) return SD_E_INVALID_PARAM;
  pc = (prompt_cmd *)sd_calloc(1, sizeof(*pc));
  plock();
  if (p->answered) { punlock(); sd_free(pc); return SD_E_INVALID_PARAM; }
  if (!p->conn) {
    p->answered = 1;
    punlock();
    sd_free(pc);
    prompt_release(p);
    return SD_E_CANCELLED;
  }
  if (!cancel) {
    if (want_kind == 0 && p->kind != SD_PROMPT_HOSTKEY) { punlock(); sd_free(pc); return SD_E_INVALID_PARAM; }
    if (want_kind == 1 && p->kind != SD_PROMPT_LEGACY_ACK) { punlock(); sd_free(pc); return SD_E_INVALID_PARAM; }
    if (want_kind == 2) {
      if (p->kind == SD_PROMPT_HOSTKEY || p->kind == SD_PROMPT_LEGACY_ACK) { punlock(); sd_free(pc); return SD_E_INVALID_PARAM; }
      if (n > SD_COUNTOF(p->ans.resp) || (n && !resp)) { punlock(); sd_free(pc); return SD_E_INVALID_PARAM; }
      if ((flags & SD_ANSWER_FROM_STORE) && p->ainfo.hostkey_just_accepted) {   /* TM-R05 */
        punlock();
        sd_free(pc);
        return SD_E_INVALID_PARAM;
      }
    }
  }
  if (!pc) { punlock(); return SD_E_NO_MEMORY; }
  p->ans.cancelled = cancel;
  p->ans.decision = d;
  p->ans.ack = ack;
  p->ans.flags = flags;
  p->ans.n = 0;
  if (!cancel && want_kind == 2) {
    for (i = 0; i < n; i++) {
      const char *s = resp[i] ? resp[i] : "";
      if (sd_secbuf_from(s, strlen(s), &p->ans.resp[i]) != SD_OK) {
        uint32_t j;
        for (j = 0; j < i; j++) { sd_secbuf_free(p->ans.resp[j]); p->ans.resp[j] = NULL; }
        punlock();
        sd_free(pc);
        return SD_E_NO_MEMORY;
      }
      p->ans.n = i + 1;
    }
  }
  p->answered = 1;
  pc->p = p;
  pc->cmd.run = prompt_cmd_run;
  pc->cmd.drop = prompt_cmd_drop;
  e = ssh_post_cmd(p->conn, &pc->cmd);
  punlock();
  if (e != SD_OK) {
    sd_free(pc);
    prompt_release(p);
    return SD_E_CANCELLED;
  }
  return SD_OK;
}

sd_err sd_prompt_answer(sd_prompt *p, uint32_t n, const char *const *utf8_responses)
{
  return answer(p, 0, SD_HK_REJECT, 0, n, utf8_responses, 0, 2);
}

sd_err sd_prompt_answer_ex(sd_prompt *p, uint32_t n, const char *const *utf8_responses, uint32_t answer_flags)
{
  return answer(p, 0, SD_HK_REJECT, 0, n, utf8_responses, answer_flags, 2);
}

sd_err sd_prompt_answer_hostkey(sd_prompt *p, sd_hostkey_decision d)
{
  if (d != SD_HK_REJECT && d != SD_HK_ACCEPT_ONCE && d != SD_HK_ACCEPT_AND_STORE) return SD_E_INVALID_PARAM;
  return answer(p, 0, d, 0, 0, NULL, 0, 0);
}

sd_err sd_prompt_answer_ack(sd_prompt *p, int accept)
{
  return answer(p, 0, SD_HK_REJECT, accept ? 1 : 0, 0, NULL, 0, 1);
}

sd_err sd_prompt_cancel(sd_prompt *p)
{
  return answer(p, 1, SD_HK_REJECT, 0, 0, NULL, 0, -1);
}
