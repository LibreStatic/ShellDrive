/* shelldrive-setup: Start menu shortcut through IShellLinkW (docs/design/04 §6.7 and the account setup).
   The CLSID and IIDs are spelled out here, so no uuid.lib is linked (the stub links nothing outside
   KnownDLLs, 04 §2.4). */
#include "setup_int.h"

#include <shlobj.h>

static const GUID sd_clsid_shelllink = { 0x00021401, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const GUID sd_iid_shelllinkw = { 0x000214F9, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const GUID sd_iid_persistfile = { 0x0000010B, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };

int sd_setup_shortcut_create(const wchar_t *lnk, const wchar_t *target, const wchar_t *workdir,
                             const wchar_t *description, const wchar_t *icon)
{
  HRESULT hr;
  IShellLinkW *link = NULL;
  IPersistFile *file = NULL;
  int rc = 1;
  BOOL initialized;

  hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  initialized = (hr == S_OK || hr == S_FALSE);
  if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
    return 1;

  hr = CoCreateInstance(&sd_clsid_shelllink, NULL, CLSCTX_INPROC_SERVER, &sd_iid_shelllinkw, (void **)&link);
  if (SUCCEEDED(hr) && link != NULL) {
    link->lpVtbl->SetPath(link, target);
    if (workdir != NULL)
      link->lpVtbl->SetWorkingDirectory(link, workdir);
    if (description != NULL)
      link->lpVtbl->SetDescription(link, description);
    if (icon != NULL)
      link->lpVtbl->SetIconLocation(link, icon, 0);
    hr = link->lpVtbl->QueryInterface(link, &sd_iid_persistfile, (void **)&file);
    if (SUCCEEDED(hr) && file != NULL) {
      hr = file->lpVtbl->Save(file, lnk, TRUE);
      if (SUCCEEDED(hr))
        rc = 0;
      file->lpVtbl->Release(file);
    }
    link->lpVtbl->Release(link);
  }

  if (initialized)
    CoUninitialize();
  return rc;
}
