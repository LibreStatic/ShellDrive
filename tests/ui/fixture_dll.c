/* Fixture for sd_add_dll (cmake/SdModule.cmake): a DLL with one export and no imports. It proves the helper
   builds the version resource, the import audit and the ISA audit; shipping DLLs (the shell extension) come
   later. */
#include <windows.h>

__declspec(dllexport) int sd_ui_fixture_value(void)
{
  return 42;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
  (void)inst;
  (void)reason;
  (void)reserved;
  return TRUE;
}
