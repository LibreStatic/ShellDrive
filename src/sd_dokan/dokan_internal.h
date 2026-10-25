/* sd_dokan internals: the dynamically loaded dokan2.dll entry points (02 §6.2). Private.
 * Thread safety: the table is filled once under a lock by sd_dokan_probe and read-only afterwards. */
#ifndef SD_DOKAN_INTERNAL_H
#define SD_DOKAN_INTERNAL_H

#include <windows.h>

#include "dokan_abi.h"
#include "sd_dokan/sd_dokan.h"

typedef struct sd_dokan_api {
  HMODULE dll;
  ULONG   lib_version, driver_version;
  SD_PFN_DokanInit                     Init;
  SD_PFN_DokanShutdown                 Shutdown;
  SD_PFN_DokanCreateFileSystem         CreateFileSystem;
  SD_PFN_DokanWaitForFileSystemClosed  WaitForFileSystemClosed;
  SD_PFN_DokanIsFileSystemRunning      IsFileSystemRunning;
  SD_PFN_DokanCloseHandle              CloseHandle;
  SD_PFN_DokanRemoveMountPoint         RemoveMountPoint;
  SD_PFN_DokanVersion                  Version;
  SD_PFN_DokanDriverVersion            DriverVersion;
  SD_PFN_DokanResetTimeout             ResetTimeout;
  SD_PFN_DokanOpenRequestorToken       OpenRequestorToken;
  SD_PFN_DokanNotifyCreate             NotifyCreate;
  SD_PFN_DokanNotifyDelete             NotifyDelete;
  SD_PFN_DokanNotifyUpdate             NotifyUpdate;
  SD_PFN_DokanNotifyRename             NotifyRename;
  SD_PFN_DokanGetMountPointList        GetMountPointList;
  SD_PFN_DokanReleaseMountPointList    ReleaseMountPointList;
} sd_dokan_api;

/* NULL until a successful sd_dokan_probe(). */
const sd_dokan_api *sd_dokan_api_get(void);

/* NTSTATUS values used by the adapter (ntstatus.h is not included next to windows.h). */
#define SD_STATUS_SUCCESS                 ((LONG)0x00000000L)
#define SD_STATUS_BUFFER_OVERFLOW         ((LONG)0x80000005L)
#define SD_STATUS_NOT_IMPLEMENTED         ((LONG)0xC0000002L)
#define SD_STATUS_INVALID_PARAMETER       ((LONG)0xC000000DL)
#define SD_STATUS_END_OF_FILE             ((LONG)0xC0000011L)
#define SD_STATUS_ACCESS_DENIED           ((LONG)0xC0000022L)
#define SD_STATUS_OBJECT_NAME_INVALID     ((LONG)0xC0000033L)
#define SD_STATUS_OBJECT_NAME_NOT_FOUND   ((LONG)0xC0000034L)
#define SD_STATUS_OBJECT_NAME_COLLISION   ((LONG)0xC0000035L)
#define SD_STATUS_OBJECT_PATH_NOT_FOUND   ((LONG)0xC000003AL)
#define SD_STATUS_SHARING_VIOLATION       ((LONG)0xC0000043L)
#define SD_STATUS_DISK_QUOTA_EXCEEDED     ((LONG)0xC0000044L)
#define SD_STATUS_DELETE_PENDING          ((LONG)0xC0000056L)
#define SD_STATUS_DISK_FULL               ((LONG)0xC000007FL)
#define SD_STATUS_FILE_INVALID            ((LONG)0xC0000098L)
#define SD_STATUS_INSUFFICIENT_RESOURCES  ((LONG)0xC000009AL)
#define SD_STATUS_MEDIA_WRITE_PROTECTED   ((LONG)0xC00000A2L)
#define SD_STATUS_IO_TIMEOUT              ((LONG)0xC00000B5L)
#define SD_STATUS_FILE_IS_A_DIRECTORY     ((LONG)0xC00000BAL)
#define SD_STATUS_NOT_SUPPORTED           ((LONG)0xC00000BBL)
#define SD_STATUS_UNEXPECTED_IO_ERROR     ((LONG)0xC00000E9L)
#define SD_STATUS_DIRECTORY_NOT_EMPTY     ((LONG)0xC0000101L)
#define SD_STATUS_NOT_A_DIRECTORY         ((LONG)0xC0000103L)
#define SD_STATUS_NAME_TOO_LONG           ((LONG)0xC0000106L)
#define SD_STATUS_CANCELLED               ((LONG)0xC0000120L)
#define SD_STATUS_CANNOT_DELETE           ((LONG)0xC0000121L)
#define SD_STATUS_CONNECTION_DISCONNECTED ((LONG)0xC000020CL)
#define SD_STATUS_FILE_TOO_LARGE          ((LONG)0xC0000904L)

#endif /* SD_DOKAN_INTERNAL_H */
