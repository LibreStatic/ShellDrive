MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

LanguageNames=(English=0x409:MSG00409)

MessageId=1000 Severity=Informational SymbolicName=SVC_MSG_STARTED
Language=English
ShellDrive service started (version %1).
.

MessageId=1001 Severity=Informational SymbolicName=SVC_MSG_STOPPED
Language=English
ShellDrive service stopped.
.

MessageId=1100 Severity=Informational SymbolicName=SVC_MSG_MOUNTED
Language=English
Global drive for profile %1 is mounted at %2.
.

MessageId=1101 Severity=Informational SymbolicName=SVC_MSG_UNMOUNTED
Language=English
Global drive for profile %1 at %2 was unmounted.
.

MessageId=2100 Severity=Error SymbolicName=SVC_MSG_MOUNT_FAILED
Language=English
Global drive for profile %1 failed to mount (%2): %3
.

MessageId=2110 Severity=Error SymbolicName=SVC_MSG_START_FAILED
Language=English
ShellDrive service could not start (%1).
.
