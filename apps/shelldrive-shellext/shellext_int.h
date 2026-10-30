/* shelldrive-shellext.dll internals (03 §1.6, §8.2, §8.5). Shared by the COM code and the registration code.
 *
 * The DLL is loaded into Explorer and into every process that shows a file dialog. Keep it small: no
 * network, no IPC pipe, no profile files, no threads, and no global constructors. */
#ifndef SD_SHELLEXT_INT_H
#define SD_SHELLEXT_INT_H

#include <windows.h>

#include "shellext_model.h"

/* Class id of the context menu handler. Fixed for the life of the product: changing it orphans every
   installed registration. Defined (storage) in shellext_com.c, which is built with INITGUID. */
DEFINE_GUID(SHX_CLSID_CONTEXT_MENU, 0xc2a44993, 0x862b, 0x42ab, 0xb4, 0x0b, 0x25, 0x4e, 0xfb, 0x1f, 0x5c, 0x43);

/* Class id of the This PC handler ("Mount with ShellDrive" submenu, "Open ShellDrive", 03 §8.2). A class of its
   own, so Explorer's registration says which menu is meant and the code never has to guess from the data object. */
DEFINE_GUID(SHX_CLSID_COMPUTER_MENU, 0x5e1c7d02, 0x3b8f, 0x4a9e, 0x9c, 0x61, 0x7d, 0x24, 0xa0, 0xf3, 0xb5, 0xe8);

/* Text of the class id in registry form (keep in step with the GUID above). */
#define SHX_CLSID_TEXT   L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}"
#define SHX_CLSID_COMPUTER_TEXT L"{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}"
#define SHX_HANDLER_NAME L"ShellDrive"
#define SHX_DESCRIPTION  L"ShellDrive context menu"
#define SHX_DESCRIPTION_COMPUTER L"ShellDrive This PC context menu"
#define SHX_UI_EXE       L"shelldrive-ui.exe"

/* Handle of this DLL, set by DllMain. */
extern HINSTANCE shx_module;

/* menu.cache (03 §8.2.2): the profiles of the This PC submenu, at most max. Returns 0 for no data. shellext_cache.c. */
size_t shx_menucache_load(shx_profile *out, size_t max);

/* Per-user registration (HKCU\Software\Classes and the Approved list). shellext_register.c. */
HRESULT shx_register_server(void);
HRESULT shx_unregister_server(void);

#endif /* SD_SHELLEXT_INT_H */
