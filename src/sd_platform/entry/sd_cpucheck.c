/* x86-sse2 entry thunk (04 §3.2, D4): refuses to start on a CPU without SSE2.
 *
 * Linked into every x86-sse2 executable by sd_add_app and set as /ENTRY. This translation unit is
 * always compiled /arch:IA32 (its own object library, cmake/SdModule.cmake), runs before the CRT
 * start-up code and therefore uses only kernel32 (and user32 for windowed apps): no CRT calls, no
 * sd_l10n. If IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE) (XP+) is FALSE it prints a
 * fixed message naming the x86-ia32 build and exits with STATUS_ILLEGAL_INSTRUCTION; otherwise it
 * tail-calls the CRT entry point the linker would have used. sd-isacheck checks that the image entry
 * point is this function and that it contains no SSE/SSE2 instruction.
 *
 * The message is user-facing, so it exists in all six UI languages (AGENTS.md). It cannot come from
 * the PO catalogs because the sd_l10n runtime is compiled /arch:SSE2 in this flavour; keep the
 * strings below in sync with the register rules (es voseo, fr vous, de/it informal imperative).
 *
 * Defines: SD_CPUCHECK_GUI (MessageBoxW + wWinMainCRTStartup instead of stderr + wmainCRTStartup),
 * SD_CPUCHECK_TEST_HOOK (non-shipping fixture only: SD_CPUCHECK_SIMULATE_NO_SSE2=1 forces the refusal). */
#include <windows.h>

#ifndef PF_XMMI64_INSTRUCTIONS_AVAILABLE
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE 10
#endif

#define SD_CPUCHECK_EXIT_CODE 0xC000001Du   /* STATUS_ILLEGAL_INSTRUCTION */

#if defined(SD_CPUCHECK_GUI)
extern int __cdecl wWinMainCRTStartup(void);
#define SD_CRT_ENTRY wWinMainCRTStartup
#else
extern int __cdecl wmainCRTStartup(void);
#define SD_CRT_ENTRY wmainCRTStartup
#endif

static const wchar_t *message(void)
{
  switch (PRIMARYLANGID(GetUserDefaultUILanguage())) {
  case LANG_SPANISH:
    return L"Esta versión de ShellDrive necesita un procesador con SSE2. "
           L"Descargá la versión x86-ia32 de ShellDrive para esta computadora.";
  case LANG_FRENCH:
    return L"Cette version de ShellDrive nécessite un processeur avec SSE2. "
           L"Téléchargez la version x86-ia32 de ShellDrive pour cet ordinateur.";
  case LANG_PORTUGUESE:
    return L"Esta versão do ShellDrive precisa de um processador com SSE2. "
           L"Baixe a versão x86-ia32 do ShellDrive para este computador.";
  case LANG_ITALIAN:
    return L"Questa versione di ShellDrive richiede un processore con SSE2. "
           L"Scarica la versione x86-ia32 di ShellDrive per questo computer.";
  case LANG_GERMAN:
    return L"Diese ShellDrive-Version braucht einen Prozessor mit SSE2. "
           L"Lade die x86-ia32-Version von ShellDrive für diesen Computer herunter.";
  default:
    return L"This ShellDrive build needs a processor with SSE2. "
           L"Download the x86-ia32 build of ShellDrive for this computer.";
  }
}

static int sse2_missing(void)
{
#if defined(SD_CPUCHECK_TEST_HOOK)
  wchar_t v[4];
  if (GetEnvironmentVariableW(L"SD_CPUCHECK_SIMULATE_NO_SSE2", v, 4) == 1 && v[0] == L'1') return 1;
#endif
  return !IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE);
}

static void report(const wchar_t *msg)
{
#if defined(SD_CPUCHECK_GUI)
  MessageBoxW(NULL, msg, L"ShellDrive", MB_OK | MB_ICONERROR);
#else
  HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
  DWORD mode, done, len = (DWORD)lstrlenW(msg);
  char utf8[512];
  int n;
  if (h == NULL || h == INVALID_HANDLE_VALUE) return;
  if (GetConsoleMode(h, &mode)) {
    WriteConsoleW(h, msg, len, &done, NULL);
    WriteConsoleW(h, L"\r\n", 2, &done, NULL);
    return;
  }
  n = WideCharToMultiByte(CP_UTF8, 0, msg, (int)len, utf8, (int)sizeof(utf8) - 2, NULL, NULL);
  if (n <= 0) return;
  utf8[n++] = '\r';
  utf8[n++] = '\n';
  WriteFile(h, utf8, (DWORD)n, &done, NULL);
#endif
}

/* The loader calls the entry point with one argument (stdcall); the CRT entry points ignore it and
   never return (they end in ExitProcess), so the declared signature does not matter for the stack. */
int __cdecl sd_cpucheck_entry(void)
{
  if (sse2_missing()) {
    report(message());
    ExitProcess(SD_CPUCHECK_EXIT_CODE);
  }
  return SD_CRT_ENTRY();
}
