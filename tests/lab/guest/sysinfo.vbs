' ShellDrive lab: prints OS and CPU facts as key=value lines (XP SP3 and later; WMI only).
Option Explicit
Dim wmi, item, sh
Set sh = CreateObject("WScript.Shell")
Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
For Each item In wmi.ExecQuery("SELECT Caption, Version, CSDVersion FROM Win32_OperatingSystem")
  WScript.Echo "os=" & Trim(item.Caption) & " " & item.CSDVersion
  WScript.Echo "os_version=" & item.Version
Next
For Each item In wmi.ExecQuery("SELECT Name, Manufacturer, Architecture FROM Win32_Processor")
  WScript.Echo "cpu=" & Trim(item.Name)
  WScript.Echo "cpu_vendor=" & item.Manufacturer
  WScript.Echo "cpu_arch=" & item.Architecture
Next
WScript.Echo "processor_identifier=" & sh.ExpandEnvironmentStrings("%PROCESSOR_IDENTIFIER%")
WScript.Echo "processor_architecture=" & sh.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%")
WScript.Echo "processor_architew6432=" & sh.ExpandEnvironmentStrings("%PROCESSOR_ARCHITEW6432%")
