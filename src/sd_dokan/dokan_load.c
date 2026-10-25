/* dokan2.dll loading and the version gate (02 §6.1-§6.3, TM-R23). The DLL is loaded only from
 * System32 by full path (sd_platform_load_system_dll), never through the search path, and only on
 * Windows 7 SP1 or later, so the XP flavour builds and runs without ever touching it.
 * Thread safety: sd_dokan_probe is serialized by a lock; the table is immutable once published. */
#include <windows.h>

#include "dokan_internal.h"
#include "sd/winapi_compat.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"

static sd_dokan_api g_api;
static volatile LONG g_ready;           /* 1 once g_api is complete */
static volatile LONG g_lock;            /* spin lock (no static CRITICAL_SECTION initializer) */

static void lock(void) { while (InterlockedCompareExchange(&g_lock, 1, 0) != 0) Sleep(1); }
static void unlock(void) { InterlockedExchange(&g_lock, 0); }

const sd_dokan_api *sd_dokan_api_get(void)
{
  return InterlockedCompareExchange(&g_ready, 0, 0) ? &g_api : NULL;
}

#define RESOLVE(field, name)                                         \
  do {                                                               \
    *(FARPROC *)&a.field = GetProcAddress(dll, name);                \
    if (!a.field) missing = name;                                    \
  } while (0)

static BOOL is_wow64(void)
{
  sd_pfn_IsWow64Process f = (sd_pfn_IsWow64Process)sd_platform_resolve(SD_API_IsWow64Process);
  BOOL w = FALSE;
  return f && f(GetCurrentProcess(), &w) && w;
}

sd_dokan_avail sd_dokan_probe(const sd_dokan_deny *deny, sd_dokan_probe_info *info)
{
  sd_dokan_probe_info tmp;
  sd_dokan_api a;
  HMODULE dll;
  const char *missing = NULL;
  uint32_t i;
  if (!info) info = &tmp;
  memset(info, 0, sizeof(*info));
  if (!sd_os_at_least(6, 1, 7601)) {
    info->avail = SD_DOKAN_OS_UNSUPPORTED;   /* Dokany 2.x: Windows 7 SP1+ (02 §6.1) */
    return info->avail;
  }
  if (is_wow64()) {
    info->avail = SD_DOKAN_WOW64;
    return info->avail;
  }
  lock();
  if (!InterlockedCompareExchange(&g_ready, 0, 0)) {
    memset(&a, 0, sizeof(a));
    SetLastError(0);
    dll = sd_platform_load_system_dll(L"dokan2.dll");
    if (!dll) {
      info->load_error = GetLastError();
      unlock();
      info->avail = SD_DOKAN_NOT_INSTALLED;
      return info->avail;
    }
    a.dll = dll;
    RESOLVE(Init, "DokanInit");
    RESOLVE(Shutdown, "DokanShutdown");
    RESOLVE(CreateFileSystem, "DokanCreateFileSystem");
    RESOLVE(WaitForFileSystemClosed, "DokanWaitForFileSystemClosed");
    RESOLVE(IsFileSystemRunning, "DokanIsFileSystemRunning");
    RESOLVE(CloseHandle, "DokanCloseHandle");
    RESOLVE(RemoveMountPoint, "DokanRemoveMountPoint");
    RESOLVE(Version, "DokanVersion");
    RESOLVE(DriverVersion, "DokanDriverVersion");
    RESOLVE(ResetTimeout, "DokanResetTimeout");
    RESOLVE(OpenRequestorToken, "DokanOpenRequestorToken");
    RESOLVE(NotifyCreate, "DokanNotifyCreate");
    RESOLVE(NotifyDelete, "DokanNotifyDelete");
    RESOLVE(NotifyUpdate, "DokanNotifyUpdate");
    RESOLVE(NotifyRename, "DokanNotifyRename");
    RESOLVE(GetMountPointList, "DokanGetMountPointList");
    RESOLVE(ReleaseMountPointList, "DokanReleaseMountPointList");
    if (missing) {
      unlock();
      SD_LOGW("dokan", "dokan2.dll lacks %s", missing);
      info->load_error = ERROR_PROC_NOT_FOUND;
      info->avail = SD_DOKAN_TOO_OLD;
      return info->avail;
    }
    a.lib_version = a.Version();
    a.driver_version = a.DriverVersion();
    g_api = a;
  }
  info->lib_version = g_api.lib_version;
  info->driver_version = g_api.driver_version;
  if (g_api.lib_version < SD_DOKAN_MINIMUM_VERSION) {
    info->avail = SD_DOKAN_TOO_OLD;           /* incl. 2.0.x: option values were renumbered in 2.1.0 */
  } else if (g_api.driver_version == 0) {
    info->avail = SD_DOKAN_DRIVER_MISSING;
  } else if (g_api.driver_version < SD_DOKAN_MINIMUM_VERSION) {
    info->avail = SD_DOKAN_TOO_OLD;
  } else {
    info->avail = SD_DOKAN_OK;
    for (i = 0; deny && i < deny->count; i++) {
      const sd_dokan_deny_range *r = &deny->ranges[i];
      if ((g_api.lib_version >= r->from && g_api.lib_version <= r->to) ||
          (g_api.driver_version >= r->from && g_api.driver_version <= r->to)) {
        info->avail = SD_DOKAN_DENIED;        /* TM-R23 */
        info->deny_reason = r->reason;
        break;
      }
    }
  }
  if (info->avail == SD_DOKAN_OK && !InterlockedCompareExchange(&g_ready, 0, 0)) {
    g_api.Init();                             /* once per process (02 §6.2) */
    InterlockedExchange(&g_ready, 1);
    SD_LOGI("dokan", "dokan2.dll %u, driver %u", (unsigned)g_api.lib_version, (unsigned)g_api.driver_version);
  }
  unlock();
  return info->avail;
}

void sd_dokan_shutdown(void)
{
  lock();
  if (InterlockedCompareExchange(&g_ready, 0, 0)) {
    g_api.Shutdown();
    InterlockedExchange(&g_ready, 0);
    memset(&g_api, 0, sizeof(g_api));         /* the module stays mapped; a new probe re-inits */
  }
  unlock();
}

sd_err sd_dokan_remove_stale_mounts(void)
{
  const sd_dokan_api *api = sd_dokan_api_get();
  SD_DOKAN_MOUNT_POINT_INFO *list;
  ULONG n = 0, i;
  static const WCHAR k_prefix[] = L"\\shelldrive\\";
  if (!api)
    return SD_E_UNSUPPORTED;
  list = api->GetMountPointList(FALSE, &n);
  if (!list)
    return SD_OK;
  for (i = 0; i < n; i++) {
    if (_wcsnicmp(list[i].UNCName, k_prefix, SD_COUNTOF(k_prefix) - 1) == 0) {
      SD_LOGI("dokan", "removing stale mount point %ls", list[i].MountPoint);
      api->RemoveMountPoint(list[i].MountPoint);
    }
  }
  api->ReleaseMountPointList(list);
  return SD_OK;
}

sd_ntstatus sd_vfs_to_ntstatus(sd_vfs_status s)
{
  switch (s) {
    case SD_VFS_OK:                return SD_STATUS_SUCCESS;
    case SD_VFS_E_NOT_FOUND:       return SD_STATUS_OBJECT_NAME_NOT_FOUND;
    case SD_VFS_E_PATH_NOT_FOUND:  return SD_STATUS_OBJECT_PATH_NOT_FOUND;
    case SD_VFS_E_EXISTS:          return SD_STATUS_OBJECT_NAME_COLLISION;
    case SD_VFS_E_ACCESS_DENIED:   return SD_STATUS_ACCESS_DENIED;
    case SD_VFS_E_READ_ONLY:       return SD_STATUS_MEDIA_WRITE_PROTECTED;
    case SD_VFS_E_SHARING:         return SD_STATUS_SHARING_VIOLATION;
    case SD_VFS_E_DELETE_PENDING:  return SD_STATUS_DELETE_PENDING;
    case SD_VFS_E_CANNOT_DELETE:   return SD_STATUS_CANNOT_DELETE;
    case SD_VFS_E_NOT_EMPTY:       return SD_STATUS_DIRECTORY_NOT_EMPTY;
    case SD_VFS_E_IS_DIR:          return SD_STATUS_FILE_IS_A_DIRECTORY;
    case SD_VFS_E_NOT_DIR:         return SD_STATUS_NOT_A_DIRECTORY;
    case SD_VFS_E_INVALID_NAME:    return SD_STATUS_OBJECT_NAME_INVALID;
    case SD_VFS_E_NAME_TOO_LONG:   return SD_STATUS_NAME_TOO_LONG;
    case SD_VFS_E_NO_SPACE:        return SD_STATUS_DISK_FULL;
    case SD_VFS_E_QUOTA:           return SD_STATUS_DISK_QUOTA_EXCEEDED;
    case SD_VFS_E_TOO_LARGE:       return SD_STATUS_FILE_TOO_LARGE;
    case SD_VFS_E_DISCONNECTED:    return SD_STATUS_CONNECTION_DISCONNECTED;
    case SD_VFS_E_STALE:           return SD_STATUS_FILE_INVALID;
    case SD_VFS_E_TIMEOUT:         return SD_STATUS_IO_TIMEOUT;
    case SD_VFS_E_UNSUPPORTED:     return SD_STATUS_NOT_SUPPORTED;
    case SD_VFS_E_NO_MEMORY:       return SD_STATUS_INSUFFICIENT_RESOURCES;
    case SD_VFS_E_IO:              return SD_STATUS_UNEXPECTED_IO_ERROR;
    case SD_VFS_E_CANCELLED:       return SD_STATUS_CANCELLED;
    case SD_VFS_E_END_OF_FILE:     return SD_STATUS_END_OF_FILE;
    default:                       return SD_STATUS_UNEXPECTED_IO_ERROR;
  }
}
