/* Global WebDAV mechanism choice (apps/shelldrive-host/svc_gw.h). Pure: no Win32 calls except the version constants. */
#include <string.h>

#include "svc_gw.h"

/* The compiled table. Every cell is UNVERIFIED, so no OS family selects system or link yet and auto resolves to attach
   everywhere. Why, per mechanism (the evidence is in docs/dev/m5-webdav-global-spike.md):

   system (mechanism A): a drive mapped by LocalSystem belongs to the SYSTEM logon session. The redirector then carries
     user accesses on that connection, so the server would see the service identity, not the accessing user (G2). This
     is reasoning from the redirector model; no lab run has confirmed it on any OS. On XP/2003 the design expects global
     visibility (D11), but G2 is the open part there too. UNVERIFIED on XP/2003, UNVERIFIED on the others.

   link (mechanism B): a global DOS device on the UNC lets each user's logon session create the implicit connection
     with its own credentials (G2 by design). The session-local form is accepted without elevation (verified on this
     machine, Windows 11), but the Global\ form that the service needs is denied to a standard user (verified), and
     G1, G3 and G5 need a LocalSystem process and a second logon session, which this machine cannot provide. UNVERIFIED
     on every family.

   Only a lab run (G1-G5 and G7, 02 §7.7) may change a cell to GO, and only with a note in the spike report. */
static const svc_gw_table k_compiled = {
  { SVC_GW_UNVERIFIED /* unknown */, SVC_GW_UNVERIFIED /* XP/2003 */, SVC_GW_UNVERIFIED /* Vista/7 */,
    SVC_GW_UNVERIFIED /* 8/8.1 */, SVC_GW_UNVERIFIED /* 10/11 */ },
  { SVC_GW_UNVERIFIED /* unknown */, SVC_GW_UNVERIFIED /* XP/2003 */, SVC_GW_UNVERIFIED /* Vista/7 */,
    SVC_GW_UNVERIFIED /* 8/8.1 */, SVC_GW_UNVERIFIED /* 10/11 */ }
};

svc_gw_family svc_gw_family_of(DWORD major, DWORD minor)
{
  if (major == 5 && (minor == 1 || minor == 2))
    return SVC_GW_OS_XP_2003;
  if (major == 6 && (minor == 0 || minor == 1))
    return SVC_GW_OS_VISTA_7;
  if (major == 6 && (minor == 2 || minor == 3))
    return SVC_GW_OS_8_81;
  if (major == 10 && minor == 0)
    return SVC_GW_OS_10_11;
  return SVC_GW_OS_UNKNOWN;
}

svc_gw_mode svc_gw_mode_parse(const char *s)
{
  if (s == NULL)
    return SVC_GW_MODE_INVALID;
  if (strcmp(s, "auto") == 0)
    return SVC_GW_MODE_AUTO;
  if (strcmp(s, "system") == 0)
    return SVC_GW_MODE_SYSTEM;
  if (strcmp(s, "link") == 0)
    return SVC_GW_MODE_LINK;
  if (strcmp(s, "attach") == 0)
    return SVC_GW_MODE_ATTACH;
  return SVC_GW_MODE_INVALID;
}

const char *svc_gw_family_name(svc_gw_family f)
{
  switch (f) {
  case SVC_GW_OS_XP_2003: return "xp-2003";
  case SVC_GW_OS_VISTA_7: return "vista-7";
  case SVC_GW_OS_8_81: return "8-8.1";
  case SVC_GW_OS_10_11: return "10-11";
  default: return "unknown";
  }
}

const char *svc_gw_mode_name(svc_gw_mode m)
{
  switch (m) {
  case SVC_GW_MODE_AUTO: return "auto";
  case SVC_GW_MODE_SYSTEM: return "system";
  case SVC_GW_MODE_LINK: return "link";
  case SVC_GW_MODE_ATTACH: return "attach";
  default: return "invalid";
  }
}

const char *svc_gw_mech_name(svc_gw_mech m)
{
  switch (m) {
  case SVC_GW_SYSTEM: return "system";
  case SVC_GW_LINK: return "link";
  case SVC_GW_ATTACH: return "attach";
  default: return "refuse";
  }
}

const char *svc_gw_reason_name(svc_gw_reason r)
{
  switch (r) {
  case SVC_GW_R_OK: return "ok";
  case SVC_GW_R_TOKEN_ONLY: return "token-only mode is never used for a global mount";
  case SVC_GW_R_MODE: return "webdav_global_mode is not auto, system, link or attach";
  case SVC_GW_R_SERVICE_DOWN: return "the service is not running";
  case SVC_GW_R_OS: return "the Windows version is not one of the supported families";
  case SVC_GW_R_CLIENT_MISSING: return "the WebClient service is not installed";
  case SVC_GW_R_CLIENT_DISABLED: return "the WebClient service is disabled";
  case SVC_GW_R_CLIENT_UNKNOWN: return "the WebClient service state could not be read";
  case SVC_GW_R_NOT_VERIFIED_SYSTEM: return "the system mechanism is not verified on this Windows version";
  case SVC_GW_R_NOT_VERIFIED_LINK: return "the link mechanism is not verified on this Windows version";
  }
  return "unknown";
}

const char *svc_gw_reason_code(svc_gw_reason r)
{
  switch (r) {
  case SVC_GW_R_OK: return "";
  case SVC_GW_R_TOKEN_ONLY: return "usage";
  case SVC_GW_R_MODE: return "usage";
  case SVC_GW_R_CLIENT_DISABLED: return "webclient_disabled";
  default: return "backend_unavailable";
  }
}

const svc_gw_table *svc_gw_compiled_table(void)
{
  return &k_compiled;
}

static void refuse(svc_gw_verdict *out, svc_gw_reason r)
{
  out->mech = SVC_GW_REFUSE;
  out->reason = r;
}

void svc_gw_decide_with(const svc_gw_table *t, const svc_gw_input *in, svc_gw_verdict *out)
{
  svc_gw_family f;
  int sys_go, link_go;

  if (out == NULL)
    return;
  refuse(out, SVC_GW_R_OS);
  if (t == NULL || in == NULL)
    return;

  /* Order matters for the log: the policy refusals come first, then the machine state. */
  if (in->token_only) {
    refuse(out, SVC_GW_R_TOKEN_ONLY);
    return;
  }
  if (in->mode == SVC_GW_MODE_INVALID) {
    refuse(out, SVC_GW_R_MODE);
    return;
  }
  if (!in->service_running) {
    refuse(out, SVC_GW_R_SERVICE_DOWN);
    return;
  }
  f = in->family;
  if (f <= SVC_GW_OS_UNKNOWN || f >= SVC_GW_OS_COUNT) {
    refuse(out, SVC_GW_R_OS);
    return;
  }
  switch (in->client) {
  case SVC_GW_CLIENT_MISSING: refuse(out, SVC_GW_R_CLIENT_MISSING); return;
  case SVC_GW_CLIENT_DISABLED: refuse(out, SVC_GW_R_CLIENT_DISABLED); return;
  case SVC_GW_CLIENT_UNKNOWN: refuse(out, SVC_GW_R_CLIENT_UNKNOWN); return;
  case SVC_GW_CLIENT_RUNNING:
  case SVC_GW_CLIENT_STOPPED:
  default: break;
  }

  sys_go = t->system[f] == SVC_GW_GO;
  link_go = t->link[f] == SVC_GW_GO;
  switch (in->mode) {
  case SVC_GW_MODE_SYSTEM:
    if (!sys_go) { refuse(out, SVC_GW_R_NOT_VERIFIED_SYSTEM); return; }
    out->mech = SVC_GW_SYSTEM;
    out->reason = SVC_GW_R_OK;
    return;
  case SVC_GW_MODE_LINK:
    if (!link_go) { refuse(out, SVC_GW_R_NOT_VERIFIED_LINK); return; }
    out->mech = SVC_GW_LINK;
    out->reason = SVC_GW_R_OK;
    return;
  case SVC_GW_MODE_ATTACH:
    out->mech = SVC_GW_ATTACH;
    out->reason = SVC_GW_R_OK;
    return;
  case SVC_GW_MODE_AUTO:
  default:
    /* the first GO mechanism of the table, system before link (03 §1.3), else the per-user attach */
    if (sys_go) out->mech = SVC_GW_SYSTEM;
    else if (link_go) out->mech = SVC_GW_LINK;
    else out->mech = SVC_GW_ATTACH;
    out->reason = SVC_GW_R_OK;
    return;
  }
}

void svc_gw_decide(const svc_gw_input *in, svc_gw_verdict *out)
{
  svc_gw_decide_with(svc_gw_compiled_table(), in, out);
}
