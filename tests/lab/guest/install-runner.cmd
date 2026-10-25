@echo off
rem One-time guest preparation for the ShellDrive lab (04 section 11.4). Run it as an administrator
rem inside the clean guest from the payload ISO (\sdlab\install-runner.cmd), then shut the guest down
rem and take the "base" checkpoint (New-LabVM.ps1 -Checkpoint). XP SP3 and later.
setlocal
set "WORK=%SystemDrive%\sdlab"
if not exist "%WORK%" mkdir "%WORK%"
copy /y "%~dp0sdlab-runner.cmd" "%WORK%\sdlab-runner.cmd" >nul || goto :fail
rem XP's schtasks has no /f; delete first so a re-run replaces the task.
schtasks /delete /tn SdLabSmoke /f >nul 2>&1
schtasks /delete /tn SdLabSmoke >nul 2>&1
schtasks /create /tn SdLabSmoke /tr "%WORK%\sdlab-runner.cmd" /sc onstart /ru "SYSTEM" || goto :fail
echo SdLabSmoke task installed. Shut down this guest now and take the "base" checkpoint.
endlocal
goto :eof
:fail
echo install-runner failed (error %ERRORLEVEL%).
exit /b 1
