/* Allocation interface used by every module (04 §2.4, review §4 "memory allocation policy").
 *
 * sd_base only declares the allocator; sd_platform implements it on the process heap
 * (HeapAlloc(GetProcessHeap())), so memory may move between modules and DLLs with their own /MT
 * CRT. Fuzz/host-only builds of sd_base link a shim instead. Never use malloc/free directly.
 * Memory is never freed across a public API boundary: APIs that return memory have their own free
 * function.
 *
 * Thread safety: all functions are thread-safe. */
#ifndef SD_MEM_H
#define SD_MEM_H

#include "sd/base.h"

/* All return NULL on failure (callers map it to SD_E_NO_MEMORY). n == 0 allocates a minimal block. */
_Ret_maybenull_ void *sd_alloc(size_t n);
_Ret_maybenull_ void *sd_calloc(size_t count, size_t size);   /* zeroed; overflow-checked */
_Ret_maybenull_ void *sd_realloc(void *p, size_t n);          /* NULL p = sd_alloc; on failure p stays valid */
void sd_free(void *p);                                         /* NULL is a no-op */

/* Wipes then frees n bytes (SecureZeroMemory in sd_platform). Use for any block that held secrets. */
void sd_secure_free(void *p, size_t n);

/* Zeroization that the compiler cannot elide; implemented in sd_base without windows.h. */
void sd_secure_zero(void *p, size_t n);

/* Failure injection for tests: when set, the hook is called before each allocation and a nonzero
   return makes that allocation fail. NULL removes it. Not for production code. */
typedef int (*sd_mem_fail_hook)(void *ctx, size_t n);
void sd_mem_set_fail_hook(sd_mem_fail_hook hook, void *ctx);

#endif /* SD_MEM_H */
