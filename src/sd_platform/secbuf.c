#include <windows.h>

#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_secbuf.h"

enum { SECBUF_VIRTUAL = 1, SECBUF_LOCKED = 2 };
#define SECBUF_PAGE 4096u

sd_err sd_secbuf_new(size_t cap, sd_secbuf **out)
{
  sd_secbuf *b;
  *out = NULL;
  b = (sd_secbuf *)sd_calloc(1, sizeof(*b));
  if (b == NULL)
    return SD_E_NO_MEMORY;
  if (cap >= SECBUF_PAGE) {
    /* Page-granular, so locking does not pin unrelated heap data; VirtualAlloc memory is zeroed. */
    b->p = (uint8_t *)VirtualAlloc(NULL, cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (b->p) {
      b->flags = SECBUF_VIRTUAL;
      if (VirtualLock(b->p, cap))
        b->flags |= SECBUF_LOCKED;
    }
  } else {
    b->p = (uint8_t *)sd_calloc(1, cap ? cap : 1);
  }
  if (b->p == NULL) {
    sd_free(b);
    return SD_E_NO_MEMORY;
  }
  b->cap = cap;
  *out = b;
  return SD_OK;
}

sd_err sd_secbuf_from(const void *data, size_t n, sd_secbuf **out)
{
  sd_err e = sd_secbuf_new(n, out);
  if (e == SD_OK && n) {
    memcpy((*out)->p, data, n);
    (*out)->len = n;
  }
  return e;
}

void sd_secbuf_free(sd_secbuf *b)
{
  if (b == NULL)
    return;
  if (b->p) {
    SecureZeroMemory(b->p, b->cap);
    if (b->flags & SECBUF_VIRTUAL) {
      if (b->flags & SECBUF_LOCKED)
        VirtualUnlock(b->p, b->cap);
      VirtualFree(b->p, 0, MEM_RELEASE);
    } else {
      sd_free(b->p);
    }
  }
  sd_free(b);
}
