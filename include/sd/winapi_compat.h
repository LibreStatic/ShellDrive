/* Declarations of post-XP Windows APIs that ShellDrive resolves at run time (04 §2.1, §2.4).
 *
 * Never call these through import libraries: the import audit fails any static import that is not
 * on the flavour's floor list. Obtain the pointer with sd_platform_resolve(SD_API_*) and check it for
 * NULL. Only own typedefs are used, so the header compiles against SDK 7.1A and 10.x alike. */
#ifndef SD_WINAPI_COMPAT_H
#define SD_WINAPI_COMPAT_H

#include <windows.h>

/* kernel32 */
typedef ULONGLONG (WINAPI *sd_pfn_GetTickCount64)(VOID);                         /* Vista */
typedef BOOL      (WINAPI *sd_pfn_SetDefaultDllDirectories)(DWORD flags);          /* 8, 7 + KB2533623 */
typedef BOOL      (WINAPI *sd_pfn_SetDllDirectoryW)(LPCWSTR path);                 /* XP SP1 */
typedef HRESULT   (WINAPI *sd_pfn_SetThreadDescription)(HANDLE thread, PCWSTR d);  /* 10 1607 */
typedef BOOL      (WINAPI *sd_pfn_IsWow64Process)(HANDLE process, PBOOL wow64);     /* XP SP2 */
typedef BOOL      (WINAPI *sd_pfn_SetProcessDEPPolicy)(DWORD flags);               /* XP SP3 x86 only */
typedef BOOL      (WINAPI *sd_pfn_GetProductInfo)(DWORD, DWORD, DWORD, DWORD, PDWORD); /* Vista */

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

/* ntdll (present on XP, resolved to avoid an ntdll import library) */
typedef LONG (WINAPI *sd_pfn_RtlGetVersion)(OSVERSIONINFOW *info);

/* advapi32: RtlGenRandom is exported as SystemFunction036 (XP) */
typedef BOOLEAN (WINAPI *sd_pfn_RtlGenRandom)(PVOID buffer, ULONG length);

/* crypt32 (Vista) */
typedef BOOL (WINAPI *sd_pfn_CryptProtectMemory)(LPVOID data, DWORD size, DWORD flags);
typedef BOOL (WINAPI *sd_pfn_CryptUnprotectMemory)(LPVOID data, DWORD size, DWORD flags);

/* bcrypt.dll (CNG, Vista). Handles are opaque pointers; status is NTSTATUS (LONG). */
typedef void *sd_bcrypt_handle;
typedef LONG (WINAPI *sd_pfn_BCryptOpenAlgorithmProvider)(sd_bcrypt_handle *alg, LPCWSTR alg_id,
                                                          LPCWSTR impl, ULONG flags);
typedef LONG (WINAPI *sd_pfn_BCryptCloseAlgorithmProvider)(sd_bcrypt_handle alg, ULONG flags);
typedef LONG (WINAPI *sd_pfn_BCryptGenRandom)(sd_bcrypt_handle alg, PUCHAR buf, ULONG len, ULONG flags);
typedef LONG (WINAPI *sd_pfn_BCryptGetProperty)(sd_bcrypt_handle obj, LPCWSTR prop, PUCHAR out,
                                                ULONG cb, ULONG *result, ULONG flags);
typedef LONG (WINAPI *sd_pfn_BCryptSetProperty)(sd_bcrypt_handle obj, LPCWSTR prop, PUCHAR in,
                                                ULONG cb, ULONG flags);
typedef LONG (WINAPI *sd_pfn_BCryptGenerateSymmetricKey)(sd_bcrypt_handle alg, sd_bcrypt_handle *key,
                                                         PUCHAR obj, ULONG cbobj, PUCHAR secret,
                                                         ULONG cbsecret, ULONG flags);
typedef LONG (WINAPI *sd_pfn_BCryptDestroyKey)(sd_bcrypt_handle key);
typedef LONG (WINAPI *sd_pfn_BCryptEncrypt)(sd_bcrypt_handle key, PUCHAR in, ULONG cbin, VOID *pad,
                                            PUCHAR iv, ULONG cbiv, PUCHAR out, ULONG cbout,
                                            ULONG *result, ULONG flags);
typedef LONG (WINAPI *sd_pfn_BCryptDecrypt)(sd_bcrypt_handle key, PUCHAR in, ULONG cbin, VOID *pad,
                                            PUCHAR iv, ULONG cbiv, PUCHAR out, ULONG cbout,
                                            ULONG *result, ULONG flags);

/* user32 DPI queries (10 1607). Resolved by the UI for per-window DPI (03 §7.3). */
typedef UINT (WINAPI *sd_pfn_GetDpiForWindow)(HWND hwnd);
typedef UINT (WINAPI *sd_pfn_GetDpiForSystem)(VOID);

/* shcore.dll GetDpiForMonitor (8.1 and later; PROCESS_DPI_AWARENESS, MONITOR_DPI_TYPE as UINT). */
typedef LONG (WINAPI *sd_pfn_GetDpiForMonitor)(HMONITOR monitor, UINT dpi_type, UINT *dpi_x, UINT *dpi_y);

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif

#endif /* SD_WINAPI_COMPAT_H */
