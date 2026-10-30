/* shelldrive-setup: CAB payload extraction through the FDI API of cabinet.dll (04 §6.1).

   cabinet.dll is not a KnownDLL, so it is loaded at run time by its full System32 path and its functions
   are resolved with GetProcAddress (04 §2.4, §6.4 rule 3). The payload is read from memory (the resource
   of the stub or a buffer in tests), so the CAB never touches the disk. Every member is checked before a
   file is created: the name (sd_setup_cab_name_ok, and the final full path must stay under the
   destination), the member size and the totals. Members are created with CREATE_NEW. */
#include "setup_int.h"

#pragma warning(push)
#pragma warning(disable : 4201)   /* the SDK 7.1A fdi.h has a nameless struct (W4) */
#include <fdi.h>
#pragma warning(pop)

#include <string.h>

typedef HFDI (DIAMONDAPI *sd_FDICreate_t)(PFNALLOC, PFNFREE, PFNOPEN, PFNREAD, PFNWRITE, PFNCLOSE, PFNSEEK,
                                          int, PERF);
typedef BOOL (DIAMONDAPI *sd_FDICopy_t)(HFDI, char *, char *, int, PFNFDINOTIFY, PFNFDIDECRYPT, void *);
typedef BOOL (DIAMONDAPI *sd_FDIDestroy_t)(HFDI);

/* In-memory CAB: the only file FDI is allowed to open. */
typedef struct cab_mem {
  const unsigned char *data;
  size_t size;
  size_t pos;
} cab_mem;

#define CAB_MEM_NAME "payload.cab"

/* State of one extraction. FDI passes it to every notification as pfdin->pv. */
typedef struct cab_ctx {
  const wchar_t *dest;           /* full path, no trailing backslash */
  sd_setup_cab_limits lim;
  unsigned long long total;
  unsigned members;
  unsigned failed_msg;           /* sd_msg_id as unsigned, 0 = none */
  wchar_t failed_text[MAX_PATH];
  long failed_code;
  int fdi_error;
  int multi;
} cab_ctx;

/* FDI callbacks take no context, so the single active extraction is reached through these statics.
   The engine runs one extraction at a time (no threads), which the API documents. */
static cab_mem *g_cab_mem;

/* FDI opens the cabinet more than once while it decodes a folder. Each open gets its own read position
   (a shared one makes the second reader start at the end of the payload, and FDI reports a corrupt
   cabinet). The open handles are tracked here so that pfnclose frees only those. */
#define SD_CAB_MAX_OPENS 8
static cab_mem *g_cab_opens[SD_CAB_MAX_OPENS];

static void *DIAMONDAPI cab_alloc(ULONG cb)
{
  return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
}

static void DIAMONDAPI cab_free(void *p)
{
  if (p != NULL)
    HeapFree(GetProcessHeap(), 0, p);
}

static INT_PTR DIAMONDAPI cab_open(char *name, int oflag, int pmode)
{
  size_t i;
  cab_mem *h;

  (void)oflag;
  (void)pmode;
  if (g_cab_mem == NULL || strcmp(name, CAB_MEM_NAME) != 0)
    return -1;                   /* nothing else is ever opened: no file system access by FDI */
  for (i = 0; i < SD_CAB_MAX_OPENS && g_cab_opens[i] != NULL; i++)
    ;
  if (i == SD_CAB_MAX_OPENS)
    return -1;
  h = (cab_mem *)HeapAlloc(GetProcessHeap(), 0, sizeof(*h));
  if (h == NULL)
    return -1;
  h->data = g_cab_mem->data;
  h->size = g_cab_mem->size;
  h->pos = 0;
  g_cab_opens[i] = h;
  return (INT_PTR)h;
}

static UINT DIAMONDAPI cab_read(INT_PTR hf, void *buf, UINT cb)
{
  cab_mem *m = (cab_mem *)hf;
  size_t left = m->size - m->pos;
  size_t n = (size_t)cb < left ? (size_t)cb : left;
  memcpy(buf, m->data + m->pos, n);
  m->pos += n;
  return (UINT)n;
}

static UINT DIAMONDAPI cab_write(INT_PTR hf, void *buf, UINT cb)
{
  DWORD written = 0;
  if (!WriteFile((HANDLE)hf, buf, cb, &written, NULL))
    return 0;
  return (UINT)written;
}

static int DIAMONDAPI cab_close(INT_PTR hf)
{
  size_t i;
  for (i = 0; i < SD_CAB_MAX_OPENS; i++) {
    if (g_cab_opens[i] != NULL && (INT_PTR)g_cab_opens[i] == hf) {
      HeapFree(GetProcessHeap(), 0, g_cab_opens[i]);
      g_cab_opens[i] = NULL;
      return 0;
    }
  }
  return CloseHandle((HANDLE)hf) ? 0 : -1;
}

static long DIAMONDAPI cab_seek(INT_PTR hf, long dist, int seektype)
{
  cab_mem *m = (cab_mem *)hf;
  long long base;
  long long np;

  if (seektype == SEEK_SET)
    base = 0;
  else if (seektype == SEEK_CUR)
    base = (long long)m->pos;
  else
    base = (long long)m->size;
  np = base + dist;
  if (np < 0 || np > (long long)m->size)
    return -1;
  m->pos = (size_t)np;
  return (long)np;
}

/* Creates each missing folder of the member's relative directory under dest. */
static int make_member_dirs(const wchar_t *dest, const wchar_t *rel)
{
  wchar_t path[MAX_PATH];
  const wchar_t *p = rel;

  if (FAILED(StringCchCopyW(path, MAX_PATH, dest)))
    return 0;
  while (1) {
    const wchar_t *slash = wcschr(p, L'\\');
    size_t len;
    if (slash == NULL)
      break;
    len = slash - rel;
    {
      size_t cur = wcslen(path);
      if (cur + 1 + len >= MAX_PATH)
        return 0;
      path[cur] = L'\\';
      memcpy(path + cur + 1, rel, len * sizeof(wchar_t));
      path[cur + 1 + len] = L'\0';
    }
    if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
      return 0;
    p = slash + 1;
    rel = p;
  }
  return 1;
}

/* True when the full path of target starts with the full path of dest followed by a backslash. */
static int path_is_under(const wchar_t *dest, const wchar_t *target)
{
  wchar_t fd[MAX_PATH], ft[MAX_PATH];
  DWORD n1 = GetFullPathNameW(dest, MAX_PATH, fd, NULL);
  DWORD n2 = GetFullPathNameW(target, MAX_PATH, ft, NULL);
  size_t dl;

  if (n1 == 0 || n1 >= MAX_PATH || n2 == 0 || n2 >= MAX_PATH)
    return 0;
  dl = wcslen(fd);
  if (fd[dl - 1] == L'\\')
    dl--;
  return _wcsnicmp(fd, ft, dl) == 0 && ft[dl] == L'\\';
}

static INT_PTR DIAMONDAPI cab_notify(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin)
{
  cab_ctx *ctx = (cab_ctx *)pfdin->pv;
  wchar_t wname[MAX_PATH];
  wchar_t target[MAX_PATH];
  HANDLE h;

  switch (fdint) {
  case fdintCABINET_INFO:
    return 0;

  case fdintNEXT_CABINET:
    ctx->multi = 1;
    return -1;

  case fdintPARTIAL_FILE:
    return -1;

  case fdintCOPY_FILE:
    if (!sd_setup_cab_name_ok(pfdin->psz1)) {
      sd_setup_ascii_to_wide(pfdin->psz1, ctx->failed_text, SD_SETUP_COUNTOF(ctx->failed_text));
      ctx->failed_msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_UNSAFE;
      return -1;
    }
    if (ctx->members >= ctx->lim.max_members || (unsigned long long)pfdin->cb > ctx->lim.max_member ||
        ctx->total + (unsigned long long)pfdin->cb > ctx->lim.max_total) {
      ctx->failed_msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_TOO_BIG;
      return -1;
    }
    if (sd_setup_ascii_to_wide(pfdin->psz1, wname, SD_SETUP_COUNTOF(wname)) != 0) {
      ctx->failed_msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_UNSAFE;
      return -1;
    }
    if (!make_member_dirs(ctx->dest, wname)) {
      ctx->failed_msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_EXTRACT;
      ctx->failed_code = (long)GetLastError();
      return -1;
    }
    if (sd_setup_path_join(target, MAX_PATH, ctx->dest, wname) != 0 || !path_is_under(ctx->dest, target)) {
      ctx->failed_msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_UNSAFE;
      sd_setup_ascii_to_wide(pfdin->psz1, ctx->failed_text, SD_SETUP_COUNTOF(ctx->failed_text));
      return -1;
    }
    h = CreateFileW(target, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
      ctx->failed_msg = SD_MSG_INSTALLER_ERROR_WRITE;
      StringCchCopyW(ctx->failed_text, SD_SETUP_COUNTOF(ctx->failed_text), target);
      ctx->failed_code = (long)GetLastError();
      return -1;
    }
    ctx->members++;
    ctx->total += (unsigned long long)pfdin->cb;
    return (INT_PTR)h;

  case fdintCLOSE_FILE_INFO:
    if (!CloseHandle((HANDLE)pfdin->hf)) {
      ctx->failed_msg = SD_MSG_INSTALLER_ERROR_WRITE;
      ctx->failed_code = (long)GetLastError();
      return 0;
    }
    return 1;

  default:
    return 0;
  }
}

/* Loads cabinet.dll from System32 and resolves the FDI entry points (cached per process). */
static int load_fdi(sd_FDICreate_t *create, sd_FDICopy_t *copy, sd_FDIDestroy_t *destroy)
{
  *create = (sd_FDICreate_t)sd_setup_proc(L"cabinet.dll", "FDICreate");
  *copy = (sd_FDICopy_t)sd_setup_proc(L"cabinet.dll", "FDICopy");
  *destroy = (sd_FDIDestroy_t)sd_setup_proc(L"cabinet.dll", "FDIDestroy");
  return *create != NULL && *copy != NULL && *destroy != NULL;
}

int sd_setup_cab_extract(const sd_setup_payload *p, const wchar_t *dest, const sd_setup_cab_limits *lim,
                         sd_setup_result *r, unsigned *files_out)
{
  sd_FDICreate_t fdi_create;
  sd_FDICopy_t fdi_copy;
  sd_FDIDestroy_t fdi_destroy;
  cab_mem mem;
  cab_ctx ctx;
  ERF erf;
  HFDI hfdi;
  char cabname[] = CAB_MEM_NAME;
  char cabpath[] = "";
  BOOL ok;
  DWORD fattr;

  if (files_out != NULL)
    *files_out = 0;
  if (p == NULL || p->data == NULL || p->size == 0 || dest == NULL)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_DAMAGED, 0);

  fattr = GetFileAttributesW(dest);
  if (fattr == INVALID_FILE_ATTRIBUTES || (fattr & FILE_ATTRIBUTE_DIRECTORY) == 0)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);

  if (!load_fdi(&fdi_create, &fdi_copy, &fdi_destroy))
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_EXTRACT, (long)GetLastError());

  memset(&ctx, 0, sizeof(ctx));
  ctx.dest = dest;
  if (lim != NULL)
    ctx.lim = *lim;
  else
    sd_setup_cab_limits_default(&ctx.lim);

  mem.data = p->data;
  mem.size = p->size;
  mem.pos = 0;

  memset(&erf, 0, sizeof(erf));
  hfdi = fdi_create(cab_alloc, cab_free, cab_open, cab_read, cab_write, cab_close, cab_seek, cpuUNKNOWN, &erf);
  if (hfdi == NULL)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_EXTRACT, (long)erf.erfOper);

  g_cab_mem = &mem;
  memset(&erf, 0, sizeof(erf));
  ok = fdi_copy(hfdi, cabname, cabpath, 0, cab_notify, NULL, &ctx);
  g_cab_mem = NULL;
  fdi_destroy(hfdi);
  {
    size_t k;
    for (k = 0; k < SD_CAB_MAX_OPENS; k++) {
      if (g_cab_opens[k] != NULL) {
        HeapFree(GetProcessHeap(), 0, g_cab_opens[k]);
        g_cab_opens[k] = NULL;
      }
    }
  }

  if (ctx.multi)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_DAMAGED, 0);
  if (!ok || ctx.failed_msg != 0) {
    if (ctx.failed_msg != 0) {
      if (r != NULL) {
        r->exit_code = SD_SETUP_EXIT_FATAL;
        r->msg = (sd_msg_id)ctx.failed_msg;
        StringCchCopyW(r->text, SD_SETUP_COUNTOF(r->text), ctx.failed_text);
        r->code = ctx.failed_code;
      }
      sd_setup_log_error("payload.extract", ctx.failed_text, (DWORD)ctx.failed_code);
      return SD_SETUP_EXIT_FATAL;
    }
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_EXTRACT, (long)erf.erfOper);
  }

  if (files_out != NULL)
    *files_out = ctx.members;
  return 0;
}
