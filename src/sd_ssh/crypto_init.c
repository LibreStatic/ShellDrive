/* sd_crypto initialisation and the random source used by sd_ssh. */
#include "sd_platform/sd_thread.h"
#include "sd_crypto/sd_crypto.h"
#include "ssh_internal.h"

static sd_once g_ready_once = SD_ONCE_INIT;
static int g_ready;

static void ready_init(void *arg)
{
  SD_UNUSED(arg);
  g_ready = sd_crypto_init(0) == SD_OK;
}

int ssh_crypto_ready(void)
{
  sd_once_run(&g_ready_once, ready_init, NULL);
  return g_ready;
}

static ssh_random_fn g_test_random;

void ssh_set_random_for_tests(ssh_random_fn fn) { g_test_random = fn; }

sd_err ssh_random(void *p, size_t n)
{
  if (g_test_random) return g_test_random(p, n);
  return sd_random(p, n);
}
