@echo off
rem ShellDrive lab smoke test (04 section 11.4). Runs inside the guest from the payload ISO
rem (\sdlab\smoke.cmd), started by sdlab-runner.cmd at boot. Works on Windows XP SP3 and later:
rem cmd.exe, cscript and shutdown.exe only. Every result line goes to COM1 (read on the host by
rem Read-LabSerial.ps1) and to %SystemDrive%\sdlab\smoke.log.
rem
rem Line protocol (ASCII):
rem   SDLAB BEGIN
rem   SDLAB INFO <key>=<value>
rem   SDLAB OUT <flavour> <step> <first output line>
rem   SDLAB RESULT <flavour> <step> <exit code>
rem   SDLAB END
setlocal enableextensions enabledelayedexpansion
set "SDLAB=%~dp0"
set "ROOT=%~d0\"
set "WORK=%SystemDrive%\sdlab"
if not exist "%WORK%" mkdir "%WORK%"
set "LOG=%WORK%\smoke.log"
if exist "%LOG%" del "%LOG%"
mode COM1: BAUD=115200 PARITY=N DATA=8 STOP=1 >nul 2>&1

call :emit "SDLAB BEGIN"
cscript //nologo "%SDLAB%sysinfo.vbs" > "%WORK%\sysinfo.txt" 2>&1
for /f "usebackq delims=" %%L in ("%WORK%\sysinfo.txt") do call :emit "SDLAB INFO %%L"
for /f "usebackq delims=" %%L in ("%SDLAB%expect.txt") do call :emit "SDLAB INFO %%L"

for %%F in (x86-ia32 x86-sse2 x64-xp x64-modern) do (
  if exist "%ROOT%%%F\shelldrive.exe" call :flavour %%F
)
call :emit "SDLAB END"

rem Power off so the host sees the run end (and the VM is restored before the next run).
if not exist "%WORK%\no-shutdown.flag" shutdown -s -f -t 5
endlocal
goto :eof

:flavour
set "F=%~1"
set "BIN=%ROOT%%F%"
call :run %F% cli-version "%BIN%\shelldrive.exe" --version
call :run %F% cli-help "%BIN%\shelldrive.exe" --help
if exist "%BIN%\shelldrive-host.exe" call :run %F% host-version "%BIN%\shelldrive-host.exe" --version
if exist "%BIN%\shelldrive-host.exe" call :run %F% host-selftest "%BIN%\shelldrive-host.exe" --selftest
if exist "%BIN%\tests" (
  for %%T in ("%BIN%\tests\sd-test-*.exe") do (
    if /i not "%%~nT"=="sd-test-host-fake" if /i not "%%~nT"=="sd-test-cli" call :run %F% test-%%~nT "%%~fT"
  )
)
goto :eof

rem :run <flavour> <step> <program> [args...]
:run
set "RF=%~1"
set "RS=%~2"
shift
shift
set "ARGS="
:collect
if "%~1"=="" goto :collected
set ARGS=!ARGS! "%~1"
shift
goto :collect
:collected
%ARGS% > "%WORK%\out.txt" 2>&1
set "RC=!ERRORLEVEL!"
set "FIRST="
for /f "usebackq delims=" %%O in ("%WORK%\out.txt") do if not defined FIRST set "FIRST=%%O"
if defined FIRST call :emit "SDLAB OUT %RF% %RS% !FIRST!"
type "%WORK%\out.txt" >> "%LOG%"
call :emit "SDLAB RESULT %RF% %RS% !RC!"
goto :eof

rem :emit "<line>" - one line to COM1 and to the log. Delayed expansion keeps &, <, >, | literal.
:emit
set "LINE=%~1"
echo(!LINE!>>"%LOG%"
echo(!LINE!>COM1
goto :eof
