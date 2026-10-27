/* shelldrive-shellext.dll internals (03 §1.6, §8.2, §8.5). Shared by the COM code and the registration code.
 *
 * The DLL is loaded into Explorer and into every process that shows a file dialog. Keep it small: no
 * network, no IPC pipe, no profile files, no threads, and no global constructors. */
#ifndef SD_SHELLEXT_INT_H
#define SD_SHELLEXT_INT_H

#include <windows.h>

/* Class id of the context menu handler. Fixed for the life of the product: changing it orphans every
   installed registration. Defined (storage) in shellext_com.c, which is built with INITGUID. */
DEFINE_GUID(SHX_CLSID_CONTEXT_MENU, 0xc2a44993, 0x862b, 0x42ab, 0xb4, 0x0b, 0x25, 0x4e, 0xfb, 0x1f, 0x5c, 0x43);

/* Text of the class id in registry form (keep in step with the GUID above). */
#define SHX_CLSID_TEXT   L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}"
#define SHX_HANDLER_NAME L"ShellDrive"
#define SHX_DESCRIPTION  L"ShellDrive context menu"
#define SHX_UI_EXE       L"shelldrive-ui.exe"

/* Handle of this DLL, set by DllMain. */
extern HINSTANCE shx_module;

/* Per-user registration (HKCU\Software\Classes and the Approved list). shellext_register.c. */
HRESULT shx_register_server(void);
HRESULT shx_unregister_server(void);

#endif /* SD_SHELLEXT_INT_H */
