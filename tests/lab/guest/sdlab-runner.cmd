@echo off
rem ShellDrive lab runner, installed once per guest by install-runner.cmd into %SystemDrive%\sdlab and
rem started at every boot by the scheduled task "SdLabSmoke" (SYSTEM, no logon needed). It looks for the
rem payload ISO and runs its smoke script; without a payload it does nothing.
for %%D in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
  if exist %%D:\sdlab\smoke.cmd (
    call %%D:\sdlab\smoke.cmd
    goto :eof
  )
)
