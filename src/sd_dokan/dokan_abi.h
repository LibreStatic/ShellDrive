/* Our own minimal declarations of the Dokany 2.x user-mode ABI (dokan2.dll), frozen at 2.3.1
 * (02 §6.2, review C38, D1).
 *
 * NOTICE: this file is written by the ShellDrive project from the public, documented Dokany 2.x
 * ABI (field order, calling convention and constant values as published for Dokany 2.1+). No
 * Dokany header was copied. Names carry an SD_ prefix so they can never clash with dokan.h.
 * dokan2.dll is loaded dynamically from System32 (no import library, no delay load).
 *
 * [lab-verify] Before M0 sign-off, check every layout and constant below against a live
 * dokan2.dll 2.3.1 (e.g. mount the mirror test and dump offsets): 2.1.0 reordered the DOKAN_OPTION_*
 * values, which is why 2.0.x is rejected by the version gate (DokanVersion() >= 210).
 *
 * Private to sd_dokan. Thread safety: data declarations only. */
#ifndef SD_DOKAN_ABI_H
#define SD_DOKAN_ABI_H

#include <windows.h>

#define SD_DOKAN_VERSION                    231   /* the ABI these declarations describe */
#define SD_DOKAN_MINIMUM_VERSION            210   /* our version gate (02 §6.2) */
#define SD_DOKAN_MINIMUM_COMPATIBLE_VERSION 200   /* Dokany's own floor */

/* DOKAN_OPTIONS.Options flags (2.1+ numbering). */
#define SD_DOKAN_OPTION_DEBUG                        0x00000001u
#define SD_DOKAN_OPTION_STDERR                       0x00000002u
#define SD_DOKAN_OPTION_ALT_STREAM                   0x00000004u
#define SD_DOKAN_OPTION_WRITE_PROTECT                0x00000008u
#define SD_DOKAN_OPTION_NETWORK                      0x00000010u
#define SD_DOKAN_OPTION_REMOVABLE                    0x00000020u
#define SD_DOKAN_OPTION_MOUNT_MANAGER                0x00000040u
#define SD_DOKAN_OPTION_CURRENT_SESSION              0x00000080u
#define SD_DOKAN_OPTION_FILELOCK_USER_MODE           0x00000100u
#define SD_DOKAN_OPTION_CASE_SENSITIVE               0x00000200u
#define SD_DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE 0x00000400u
#define SD_DOKAN_OPTION_DISPATCH_DRIVER_LOGS         0x00000800u
#define SD_DOKAN_OPTION_ALLOW_IPC_BATCHING           0x00001000u

/* DokanCreateFileSystem / DokanMain results. */
#define SD_DOKAN_SUCCESS               0
#define SD_DOKAN_ERROR                (-1)
#define SD_DOKAN_DRIVE_LETTER_ERROR   (-2)
#define SD_DOKAN_DRIVER_INSTALL_ERROR (-3)
#define SD_DOKAN_START_ERROR          (-4)
#define SD_DOKAN_MOUNT_ERROR          (-5)
#define SD_DOKAN_MOUNT_POINT_ERROR    (-6)
#define SD_DOKAN_VERSION_ERROR        (-7)

#define SD_DOKAN_VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE (1024 * 16)

typedef LONG SD_DOKAN_NTSTATUS;
typedef struct sd_dokan_instance_ *SD_DOKAN_HANDLE;    /* opaque instance handle (2.x) */

typedef struct SD_DOKAN_OPTIONS {
  USHORT  Version;                 /* min(SD_DOKAN_VERSION, DokanVersion()) */
  BOOLEAN SingleThread;
  ULONG   Options;                 /* SD_DOKAN_OPTION_* */
  ULONG64 GlobalContext;
  LPCWSTR MountPoint;              /* "Z:\\" or an empty NTFS folder */
  LPCWSTR UNCName;                 /* "\\shelldrive\\<share>" with SD_DOKAN_OPTION_NETWORK */
  ULONG   Timeout;                 /* ms */
  ULONG   AllocationUnitSize;
  ULONG   SectorSize;
  ULONG   VolumeSecurityDescriptorLength;
  CHAR    VolumeSecurityDescriptor[SD_DOKAN_VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE];
} SD_DOKAN_OPTIONS;

typedef struct SD_DOKAN_FILE_INFO {
  ULONG64           Context;       /* ours: the sd_vfs_handle */
  ULONG64           DokanContext;  /* reserved */
  SD_DOKAN_OPTIONS *DokanOptions;
  PVOID             ProcessingContext;   /* reserved (2.x) */
  ULONG             ProcessId;
  UCHAR             IsDirectory;
  UCHAR             DeletePending;
  UCHAR             PagingIo;
  UCHAR             SynchronousIo;
  UCHAR             Nocache;
  UCHAR             WriteToEndOfFile;
} SD_DOKAN_FILE_INFO;

typedef struct SD_DOKAN_UNICODE_STRING {   /* layout of the NT UNICODE_STRING */
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} SD_DOKAN_UNICODE_STRING;

typedef struct SD_DOKAN_ACCESS_STATE {
  BOOLEAN SecurityEvaluated;
  BOOLEAN GenerateAudit;
  BOOLEAN GenerateOnClose;
  BOOLEAN AuditPrivileges;
  ULONG   Flags;
  ACCESS_MASK RemainingDesiredAccess;
  ACCESS_MASK PreviouslyGrantedAccess;
  ACCESS_MASK OriginalDesiredAccess;
  PSECURITY_DESCRIPTOR SecurityDescriptor;
  SD_DOKAN_UNICODE_STRING ObjectName;
  SD_DOKAN_UNICODE_STRING ObjectType;
} SD_DOKAN_ACCESS_STATE;

typedef struct SD_DOKAN_IO_SECURITY_CONTEXT {
  SD_DOKAN_ACCESS_STATE AccessState;
  ACCESS_MASK DesiredAccess;
} SD_DOKAN_IO_SECURITY_CONTEXT;

typedef struct SD_DOKAN_FIND_STREAM_DATA {   /* layout of WIN32_FIND_STREAM_DATA (not in SDK 7.1A for XP) */
  LARGE_INTEGER StreamSize;
  WCHAR cStreamName[MAX_PATH + 36];
} SD_DOKAN_FIND_STREAM_DATA;

typedef struct SD_DOKAN_MOUNT_POINT_INFO {
  ULONG Type;
  WCHAR MountPoint[MAX_PATH];
  WCHAR UNCName[64];
  WCHAR DeviceName[64];
  ULONG SessionId;
  ULONG MountOptions;
} SD_DOKAN_MOUNT_POINT_INFO;

typedef int  (WINAPI *SD_DOKAN_FILL_FIND_DATA)(PWIN32_FIND_DATAW data, SD_DOKAN_FILE_INFO *info);
typedef BOOL (WINAPI *SD_DOKAN_FILL_FIND_STREAM_DATA)(SD_DOKAN_FIND_STREAM_DATA *data, PVOID find_ctx);

/* Callback table; every callback is __stdcall and may run concurrently on Dokany worker threads. */
typedef struct SD_DOKAN_OPERATIONS {
  SD_DOKAN_NTSTATUS (WINAPI *ZwCreateFile)(LPCWSTR FileName, SD_DOKAN_IO_SECURITY_CONTEXT *SecurityContext,
                                           ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess,
                                           ULONG CreateDisposition, ULONG CreateOptions,
                                           SD_DOKAN_FILE_INFO *DokanFileInfo);
  void (WINAPI *Cleanup)(LPCWSTR FileName, SD_DOKAN_FILE_INFO *DokanFileInfo);
  void (WINAPI *CloseFile)(LPCWSTR FileName, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *ReadFile)(LPCWSTR FileName, LPVOID Buffer, DWORD BufferLength, LPDWORD ReadLength,
                                       LONGLONG Offset, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *WriteFile)(LPCWSTR FileName, LPCVOID Buffer, DWORD NumberOfBytesToWrite,
                                        LPDWORD NumberOfBytesWritten, LONGLONG Offset,
                                        SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *FlushFileBuffers)(LPCWSTR FileName, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *GetFileInformation)(LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION Buffer,
                                                 SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *FindFiles)(LPCWSTR PathName, SD_DOKAN_FILL_FIND_DATA FillFindData,
                                        SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *FindFilesWithPattern)(LPCWSTR PathName, LPCWSTR SearchPattern,
                                                   SD_DOKAN_FILL_FIND_DATA FillFindData,
                                                   SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *SetFileAttributes)(LPCWSTR FileName, DWORD FileAttributes,
                                                SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *SetFileTime)(LPCWSTR FileName, CONST FILETIME *CreationTime,
                                          CONST FILETIME *LastAccessTime, CONST FILETIME *LastWriteTime,
                                          SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *DeleteFile)(LPCWSTR FileName, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *DeleteDirectory)(LPCWSTR FileName, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *MoveFile)(LPCWSTR FileName, LPCWSTR NewFileName, BOOL ReplaceIfExisting,
                                       SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *SetEndOfFile)(LPCWSTR FileName, LONGLONG ByteOffset,
                                           SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *SetAllocationSize)(LPCWSTR FileName, LONGLONG AllocSize,
                                                SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *LockFile)(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length,
                                       SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *UnlockFile)(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length,
                                         SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *GetDiskFreeSpace)(PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
                                               PULONGLONG TotalNumberOfFreeBytes,
                                               SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *GetVolumeInformation)(LPWSTR VolumeNameBuffer, DWORD VolumeNameSize,
                                                   LPDWORD VolumeSerialNumber, LPDWORD MaximumComponentLength,
                                                   LPDWORD FileSystemFlags, LPWSTR FileSystemNameBuffer,
                                                   DWORD FileSystemNameSize, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *Mounted)(LPCWSTR MountPoint, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *Unmounted)(SD_DOKAN_FILE_INFO *DokanFileInfo);  /* only post to the control thread */
  SD_DOKAN_NTSTATUS (WINAPI *GetFileSecurity)(LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
                                              PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
                                              PULONG LengthNeeded, SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *SetFileSecurity)(LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
                                              PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
                                              SD_DOKAN_FILE_INFO *DokanFileInfo);
  SD_DOKAN_NTSTATUS (WINAPI *FindStreams)(LPCWSTR FileName, SD_DOKAN_FILL_FIND_STREAM_DATA FillFindStreamData,
                                          PVOID FindStreamContext, SD_DOKAN_FILE_INFO *DokanFileInfo);
} SD_DOKAN_OPERATIONS;

/* Exports used through GetProcAddress (02 §6.2). All __stdcall. */
typedef VOID   (WINAPI *SD_PFN_DokanInit)(VOID);
typedef VOID   (WINAPI *SD_PFN_DokanShutdown)(VOID);
typedef int    (WINAPI *SD_PFN_DokanCreateFileSystem)(SD_DOKAN_OPTIONS *options, SD_DOKAN_OPERATIONS *ops,
                                                      SD_DOKAN_HANDLE *instance);
typedef DWORD  (WINAPI *SD_PFN_DokanWaitForFileSystemClosed)(SD_DOKAN_HANDLE instance, DWORD ms);
typedef BOOL   (WINAPI *SD_PFN_DokanIsFileSystemRunning)(SD_DOKAN_HANDLE instance);
typedef VOID   (WINAPI *SD_PFN_DokanCloseHandle)(SD_DOKAN_HANDLE instance);
typedef BOOL   (WINAPI *SD_PFN_DokanRemoveMountPoint)(LPCWSTR mount_point);
typedef ULONG  (WINAPI *SD_PFN_DokanVersion)(VOID);
typedef ULONG  (WINAPI *SD_PFN_DokanDriverVersion)(VOID);
typedef BOOL   (WINAPI *SD_PFN_DokanResetTimeout)(ULONG timeout_ms, SD_DOKAN_FILE_INFO *info);
typedef HANDLE (WINAPI *SD_PFN_DokanOpenRequestorToken)(SD_DOKAN_FILE_INFO *info);
typedef BOOL   (WINAPI *SD_PFN_DokanIsNameInExpression)(LPCWSTR expression, LPCWSTR name, BOOL ignore_case);
typedef BOOL   (WINAPI *SD_PFN_DokanNotifyCreate)(SD_DOKAN_HANDLE instance, LPCWSTR path, BOOL is_dir);
typedef BOOL   (WINAPI *SD_PFN_DokanNotifyDelete)(SD_DOKAN_HANDLE instance, LPCWSTR path, BOOL is_dir);
typedef BOOL   (WINAPI *SD_PFN_DokanNotifyUpdate)(SD_DOKAN_HANDLE instance, LPCWSTR path);
typedef BOOL   (WINAPI *SD_PFN_DokanNotifyRename)(SD_DOKAN_HANDLE instance, LPCWSTR old_path, LPCWSTR new_path,
                                                  BOOL is_dir, BOOL same_dir);
typedef SD_DOKAN_MOUNT_POINT_INFO *(WINAPI *SD_PFN_DokanGetMountPointList)(BOOL unc_only, PULONG count);
typedef VOID   (WINAPI *SD_PFN_DokanReleaseMountPointList)(SD_DOKAN_MOUNT_POINT_INFO *list);
typedef SD_DOKAN_NTSTATUS (WINAPI *SD_PFN_DokanNtStatusFromWin32)(DWORD error);

#endif /* SD_DOKAN_ABI_H */
