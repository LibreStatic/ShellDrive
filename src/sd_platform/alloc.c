/* Process-heap allocator behind sd_base/sd_mem.h (04 §2.4). */
#include <windows.h>

#include "sd_base/sd_checked.h"
#include "sd_base/sd_mem.h"

static sd_mem_fail_hook volatile g_fail_hook;
static void *volatile g_fail_ctx;

void sd_mem_set_fail_hook(sd_mem_fail_hook hook, void *ctx)
{
  g_fail_ctx = ctx;
  g_fail_hook = hook;
}

static int should_fail(size_t n)
{
  sd_mem_fail_hook h = g_fail_hook;
  return h != NULL && h(g_fail_ctx, n) != 0;
}

_Ret_maybenull_ void *sd_alloc(size_t n)
{
  if (should_fail(n))
    return NULL;
  return HeapAlloc(GetProcessHeap(), 0, n ? n : 1);
}

_Ret_maybenull_ void *sd_calloc(size_t count, size_t size)
{
  size_t n;
  if (sd_mul_ovf(count, size, &n) || should_fail(n))
    return NULL;
  return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n ? n : 1);
}

_Ret_maybenull_ void *sd_realloc(void *p, size_t n)
{
  if (p == NULL)
    return sd_alloc(n);
  if (should_fail(n))
    return NULL;
  return HeapReAlloc(GetProcessHeap(), 0, p, n ? n : 1);
}

void sd_free(void *p)
{
  if (p)
    HeapFree(GetProcessHeap(), 0, p);
}

void sd_secure_free(void *p, size_t n)
{
  if (p == NULL)
    return;
  SecureZeroMemory(p, n);
  HeapFree(GetProcessHeap(), 0, p);
}
