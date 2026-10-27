/* System proxy (01 §5.2, 03 §3.8, TM-R10): the pure opt-in / policy decision and the configuration
 * boundary. ssh_sysproxy_resolve is a blocking WinHTTP worker call and stays uncovered here; the
 * decision function is driven with resolution results instead. */
#include <winsock2.h>
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "conn_internal.h"

static void resolved(ssh_sysproxy *r, sd_proxy_kind kind, const wchar_t *host, uint16_t port, int discovered)
{
  memset(r, 0, sizeof(*r));
  r->kind = kind;
  r->port = port;
  r->discovered = discovered;
  wcscpy_s(r->host, SD_COUNTOF(r->host), host);
}

/* The decision matrix: opt-in off = never a discovered proxy; opt-in on + policy off = refused;
   opt-in on + policy on = the discovered proxy is used (SSPI per TM-R10). */
SD_TEST(ssh_proxy_system_decision)
{
  ssh_sysproxy res;
  ssh_sys_decision d;

  resolved(&res, SD_PROXY_HTTP, L"wpad.corp.example", 3128, 1);
  /* opt-in off: never a discovered proxy, whatever the resolution returned */
  SD_CHECK_EQ_INT(ssh_sysproxy_decide(0, 1, 1, &res, &d), SD_OK);
  SD_CHECK(d.kind == SD_PROXY_NONE && !d.discovered && !d.sspi_allowed);

  /* opt-in on, policy AllowSystemProxy off: the opt-in is refused */
  SD_CHECK_EQ_INT(ssh_sysproxy_decide(1, 0, 1, &res, &d), SD_E_PROXY);

  /* opt-in on, policy on: the discovered proxy is used; SSPI stays off without AllowSystemProxySspi */
  SD_CHECK_EQ_INT(ssh_sysproxy_decide(1, 1, 0, &res, &d), SD_OK);
  SD_CHECK(d.kind == SD_PROXY_HTTP && d.discovered && !d.sspi_allowed);
  SD_CHECK(wcscmp(d.host, L"wpad.corp.example") == 0 && d.port == 3128);
  SD_CHECK_EQ_INT(ssh_sysproxy_decide(1, 1, 1, &res, &d), SD_OK);   /* policy lifts the SSPI ban */
  SD_CHECK(d.kind == SD_PROXY_HTTP && d.discovered && d.sspi_allowed);

  /* a static entry counts as configured: SSPI whatever AllowSystemProxySspi says */
  resolved(&res, SD_PROXY_SOCKS5, L"proxy.corp.example", 1080, 0);
  SD_CHECK_EQ_INT(ssh_sysproxy_decide(1, 1, 0, &res, &d), SD_OK);
  SD_CHECK(d.kind == SD_PROXY_SOCKS5 && !d.discovered && d.sspi_allowed);

  /* nothing resolved (bypassed, discovery failed with fallback): direct connection */
  memset(&res, 0, sizeof(res));
  SD_CHECK_EQ_INT(ssh_sysproxy_decide(1, 1, 0, &res, &d), SD_OK);
  SD_CHECK(d.kind == SD_PROXY_NONE && !d.sspi_allowed);
}

/* The configuration boundary: proxy = system without policy AllowSystemProxy fails at connect
   creation, before any resolution; with the policy bit the opt-in is accepted. */
SD_TEST(ssh_proxy_system_policy_boundary)
{
  sd_ssh_config cfg;
  sd_ssh_hop hop;
  sd_ssh_conn *c = NULL;
  memset(&cfg, 0, sizeof(cfg));
  memset(&hop, 0, sizeof(hop));
  hop.host = L"127.0.0.1";
  hop.port = 22;
  hop.auth.user = "tester";
  hop.auth.methods = SD_AUTH_PASSWORD;
  hop.proxy.kind = SD_PROXY_SYSTEM;
  cfg.struct_size = sizeof(cfg);
  cfg.hops = &hop;
  cfg.hop_count = 1;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_PROXY);   /* opt-in without the policy */
  hop.proxy.allow_system = 1;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_OK);
  SD_REQUIRE(c != NULL);
  SD_CHECK(!sd_ssh_conn_is_io_thread(c));
  sd_ssh_conn_destroy(c);
}
