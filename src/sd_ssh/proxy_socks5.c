/* SOCKS5 client (RFC 1928) with username/password authentication (RFC 1929); 01 §5.2.
 *
 * Greeting offers 00 (no authentication) and, when a user is configured, 02. GSSAPI is never
 * offered. CONNECT uses ATYP 03 (the proxy resolves the name) unless the target is a literal or
 * remote_dns = 0, then ATYP 01/04. Replies are read exactly (no byte past the reply is consumed),
 * so the SSH identification line that may follow in the same segment stays for the SSH layer.
 * "No acceptable method" and an RFC 1929 failure are SD_E_PROXY_AUTH; every other failure is
 * SD_E_PROXY with the reply code in px->why. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "proxy_internal.h"

enum { S_GREET = 1, S_NEED_PW, S_AUTH, S_CONNECT, S_DONE, S_FAIL };

static ssh_px_status s_fail(ssh_px *px, sd_err e, const char *why)
{
  size_t n = strlen(why);
  if (n >= sizeof(px->why)) n = sizeof(px->why) - 1;
  memcpy(px->why, why, n);
  px->why[n] = 0;
  px->err = e;
  px->step = S_FAIL;
  return PX_FAIL;
}

const char *ssh_socks5_reply_name(uint8_t code)
{
  switch (code) {
  case 0: return "succeeded";
  case 1: return "general SOCKS server failure";
  case 2: return "connection not allowed by ruleset";
  case 3: return "network unreachable";
  case 4: return "host unreachable";
  case 5: return "connection refused";
  case 6: return "TTL expired";
  case 7: return "command not supported";
  case 8: return "address type not supported";
  default: return "unknown reply";
  }
}

static int offer_userpass(const ssh_px *px)
{
  return px->user[0] && (px->auth == 0 || (px->auth & SD_PROXY_AUTH_USERPASS));
}

void ssh_px_socks5_start(ssh_px *px, sd_wr *out)
{
  sd_wr_u8(out, 5);
  if (offer_userpass(px)) { sd_wr_u8(out, 2); sd_wr_u8(out, 0); sd_wr_u8(out, 2); }
  else { sd_wr_u8(out, 1); sd_wr_u8(out, 0); }
  px->step = S_GREET;
  px->slen = 0;
  px->sneed = 2;
}

static void send_connect(ssh_px *px, sd_wr *out)
{
  sd_wr_u8(out, 5);
  sd_wr_u8(out, 1);   /* CONNECT */
  sd_wr_u8(out, 0);
  if (px->target_atyp == 1) { sd_wr_u8(out, 1); sd_wr_bytes(out, px->target_addr, 4); }
  else if (px->target_atyp == 4) { sd_wr_u8(out, 4); sd_wr_bytes(out, px->target_addr, 16); }
  else {
    size_t n = strlen(px->target);
    sd_wr_u8(out, 3);
    sd_wr_u8(out, (uint8_t)n);
    sd_wr_bytes(out, px->target, n);
  }
  sd_wr_u8(out, (uint8_t)(px->target_port >> 8));
  sd_wr_u8(out, (uint8_t)px->target_port);
  px->step = S_CONNECT;
  px->slen = 0;
  px->sneed = 5;      /* VER REP RSV ATYP + first address byte (the domain length for ATYP 3) */
}

static void send_userpass(ssh_px *px, sd_wr *out)
{
  size_t ul = strlen(px->user), pl = px->password ? SD_MIN(px->password->len, (size_t)255) : 0;
  sd_wr_u8(out, 1);
  sd_wr_u8(out, (uint8_t)ul);
  sd_wr_bytes(out, px->user, ul);
  sd_wr_u8(out, (uint8_t)pl);
  if (pl) sd_wr_bytes(out, px->password->p, pl);
  px->step = S_AUTH;
  px->slen = 0;
  px->sneed = 2;
}

ssh_px_status ssh_px_socks5_input(ssh_px *px, const uint8_t *p, size_t n, size_t *used, sd_wr *out)
{
  size_t i = 0;
  *used = 0;
  for (;;) {
    if (px->step != S_GREET && px->step != S_AUTH && px->step != S_CONNECT) {
      *used = i;
      if (px->step == S_FAIL) return PX_FAIL;
      if (i < n) return s_fail(px, SD_E_PROXY, "unexpected data from the SOCKS5 proxy");
      return px->step == S_NEED_PW ? PX_NEED_PASSWORD : PX_MORE;
    }
    while (px->slen < px->sneed && i < n) px->sbuf[px->slen++] = p[i++];
    *used = i;
    if (px->slen < px->sneed) return PX_MORE;
    switch (px->step) {
    case S_GREET:
      if (px->sbuf[0] != 5) return s_fail(px, SD_E_PROXY, "not a SOCKS5 proxy");
      if (px->sbuf[1] == 0) { send_connect(px, out); break; }
      if (px->sbuf[1] == 2 && offer_userpass(px)) {
        px->step = S_NEED_PW;
        px->rounds++;
        *used = i;
        return PX_NEED_PASSWORD;
      }
      if (px->sbuf[1] == 0xFF) return s_fail(px, SD_E_PROXY_AUTH, "SOCKS5 proxy accepts none of the offered methods");
      return s_fail(px, SD_E_PROXY, "SOCKS5 proxy chose a method that was not offered");
    case S_AUTH:
      if (px->sbuf[0] != 1) return s_fail(px, SD_E_PROXY, "bad SOCKS5 authentication reply");
      if (px->sbuf[1] != 0) {
        px->password_failed = 1;
        return s_fail(px, SD_E_PROXY_AUTH, "SOCKS5 proxy rejected the username/password");
      }
      sd_secbuf_free(px->password);
      px->password = NULL;
      send_connect(px, out);
      break;
    case S_CONNECT:
      if (px->sneed == 5) {
        uint8_t atyp = px->sbuf[3];
        if (px->sbuf[0] != 5) return s_fail(px, SD_E_PROXY, "bad SOCKS5 reply");
        px->status = px->sbuf[1];
        if (px->sbuf[1] != 0) {
          char why[96];
          const char *nm = ssh_socks5_reply_name(px->sbuf[1]);
          size_t l = strlen(nm);
          memcpy(why, "SOCKS5 CONNECT failed: ", 23);
          if (l > 60) l = 60;
          memcpy(why + 23, nm, l);
          why[23 + l] = 0;
          return s_fail(px, SD_E_PROXY, why);
        }
        if (atyp == 1) px->sneed = 4 + 4 + 2;
        else if (atyp == 4) px->sneed = 4 + 16 + 2;
        else if (atyp == 3) px->sneed = 4 + 1 + (size_t)px->sbuf[4] + 2;
        else return s_fail(px, SD_E_PROXY, "bad SOCKS5 reply address type");
        continue;
      }
      px->step = S_DONE;
      *used = i;
      sd_secure_zero(px->sbuf, sizeof(px->sbuf));
      return PX_DONE;
    default:
      break;
    }
  }
}

ssh_px_status ssh_px_socks5_resume(ssh_px *px, sd_wr *out)
{
  if (px->step == S_FAIL) return PX_FAIL;
  if (px->step != S_NEED_PW) return PX_MORE;
  if (!px->password) return s_fail(px, SD_E_PROXY_AUTH, "no proxy password");
  send_userpass(px, out);
  return PX_MORE;
}
