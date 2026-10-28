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

MessageId=3101 Severity=Warning SymbolicName=SVC_MSG_CLIENT_REFUSED
Language=English
ShellDrive refused a service pipe client of user %1 (%2: token, per_sid, reserved or rate). At most one such event is written per user every 10 minutes.
.

MessageId=3102 Severity=Warning SymbolicName=SVC_MSG_UNTRUSTED_FOLDER
Language=English
ShellDrive refused the untrusted machine folder or service file %1 (%2). A refused folder keeps the service idle until an elevated shelldrive service repair-data renames it aside; a refused file fails the mount that uses it.
.
