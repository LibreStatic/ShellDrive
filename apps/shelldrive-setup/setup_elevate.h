/* shelldrive-setup: two-stage elevation for per-machine installs (docs/design/04 §6.4, TM-R33, TM-R34, T-62, T-63).
 *
 *   parent  (asInvoker, keeps the UI)   creates the progress pipe, starts stage 1 with "runas" (or in this process when
 *                                        the token is already elevated) on a worker thread, relays the "P" lines to the
 *                                        progress view while it waits, then reads the stage 2 result from the pipe.
 *   stage 1 (elevated, no window)       secures %ProgramData%\LibreStatic\ShellDrive, creates a new protected stage folder
 *                                        setup\<hex>, copies its own image into it (FILE_SHARE_READ source), starts that copy
 *                                        as stage 2 with the same elevated token and waits. Then copies the stage log to the
 *                                        /log= path, when one was given (the parent passes it to stage 1 only).
 *   stage 2 (elevated, in the stage)    re-derives everything from its own image: the folder must be a stage folder under the
 *                                        expected root with a trusted owner, the pipe name must have the expected shape. It
 *                                        extracts the payload into the stage folder, runs msiexec for the MSI and reports
 *                                        "P <percent>" and "R <exit code>" lines through the pipe.
 *
 * Every process start, every elevation check and every msiexec call goes through the sd_setup_elev_ops seam. Tests supply a
 * seam that records the command lines and never elevates or runs msiexec. */
#ifndef SD_SETUP_ELEVATE_H
#define SD_SETUP_ELEVATE_H

#include <windows.h>
#include <stddef.h>

#include "setup_core.h"

typedef struct sd_setup_elev_ops {
  void *ctx;
  /* 1 when this process holds an administrator token (the real check: sd_setup_detect_host). */
  int (*is_elevated)(void *ctx);
  /* Secures <base>\LibreStatic and <base>\LibreStatic\ShellDrive (04 §6.4, TM-R34). 0 or a Win32 error. */
  DWORD (*secure_programdata)(void *ctx, const wchar_t *base);
  /* Creates a new folder under setup_dir with its protected DACL in one call; extra_ace is appended to the DACL (tests). */
  DWORD (*create_stage)(void *ctx, const wchar_t *setup_dir, const wchar_t *extra_ace, wchar_t *out, size_t cch);
  /* Copies src to a new file dst. src is opened with FILE_SHARE_READ only (04 §6.4, stage 1 step d). */
  DWORD (*copy_image)(void *ctx, const wchar_t *src, const wchar_t *dst);
  /* Starts exe with cmdline in dir and waits for it. runas uses the "runas" verb (UAC or the XP Run As dialog); otherwise
     the process inherits this token. *exit_code gets the exit code. Also used for msiexec.exe. */
  DWORD (*run)(void *ctx, const wchar_t *exe, const wchar_t *cmdline, const wchar_t *dir, int runas, DWORD *exit_code);
  /* 1 when dir is a real folder (not a reparse point) whose owner is trusted (SYSTEM or Administrators, 03 §3.2). */
  int (*folder_trusted)(void *ctx, const wchar_t *dir);
  /* Stage 2 of an uninstall: the braced product code of the ShellDrive MSI in the machine registry (sd_setup_machine_product).
     1 when found. The code is the only thing msiexec /x receives; nothing from the command line. */
  int (*find_machine_product)(void *ctx, wchar_t *code, size_t cch);
  /* The parent's install folder of the machine install (sd_setup_machine_install_dir). 1 when known. */
  int (*machine_dir)(void *ctx, wchar_t *out, size_t cch);
  /* Starts exe with cmdline in dir and returns at once, with this process's token (never runas, never the elevated stage).
     1 when started. */
  int (*launch)(void *ctx, const wchar_t *exe, const wchar_t *cmdline, const wchar_t *dir);
} sd_setup_elev_ops;

/* The shipping seam. */
void sd_setup_elev_real_ops(sd_setup_elev_ops *out);

/* The stage root: <base>\LibreStatic\ShellDrive\setup (base is %ProgramData%, no trailing backslash). */
int sd_setup_elev_root(const wchar_t *base, wchar_t *out, size_t cch);

/* Pipe names: "ShellDrive-setup-" plus 32 lower-case hex digits. 1 when the name has that shape. */
int sd_setup_elev_pipe_name_ok(const wchar_t *name);
int sd_setup_elev_pipe_new_name(wchar_t *out, size_t cch);

/* Server end (parent): one instance, read side, DACL for the current user SID only. Returns 0 or a Win32 error. */
DWORD sd_setup_elev_pipe_create(const wchar_t *name, HANDLE *out);
/* Client end (stage 2): opens the instance for writing. */
DWORD sd_setup_elev_pipe_open(const wchar_t *name, HANDLE *out);
/* Writes one line (text plus a line break) to an open client end. */
DWORD sd_setup_elev_pipe_write(HANDLE client, const wchar_t *text);
/* Server end, after the client has finished: reads every buffered line into out (NUL-terminated). Never waits for a client
   that did not connect. Returns 0 when the pipe was read (possibly empty), or a Win32 error. */
DWORD sd_setup_elev_pipe_collect(HANDLE server, wchar_t *out, size_t cch);
/* The exit code of the last "R <n>" line of collected text. 1 when there is none. */
int sd_setup_elev_result_line(const wchar_t *text, DWORD *exit_code);

/* The forwarded switches of an elevated stage: quiet, passive, norestart, force, update, dokany, lang and the accepted
   PROPERTY=value tokens. Never a path (04 §6.4: no path from the command line is trusted by the elevated stages). */
int sd_setup_elev_forward(const sd_setup_args *args, wchar_t *out, size_t cch);

/* Parent of a per-machine install (asInvoker). Creates the pipe, starts stage 1 with runas (or runs it here when this
   process is already elevated), waits, and reads the result. r gets the exit code and, for a failure, its message. A UAC
   refusal gives SD_SETUP_EXIT_CANCEL with no message. */
int sd_setup_elev_parent(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                         const sd_setup_args *args, sd_setup_result *r);

/* The progress of the stage while the parent waits: progress(ctx, n) for each new "P <n>" percentage (0..100), and
   progress(ctx, SD_SETUP_ELEV_TICK) about every 100 ms, so that the caller can pump its window. progress may be NULL. */
#define SD_SETUP_ELEV_TICK 0xFFFFFFFFu
typedef void (*sd_setup_elev_progress_fn)(void *ctx, unsigned value);
int sd_setup_elev_parent_ex(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                            const sd_setup_args *args, sd_setup_result *r, sd_setup_elev_progress_fn progress,
                            void *ctx);

/* Stage 1 (elevated). Returns 0 when stage 2 reported success, else a Win32 error or the stage 2 exit code. */
DWORD sd_setup_elev_stage1(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                           const sd_setup_args *args, DWORD *child_exit);

/* Stage 2 (elevated, in the stage folder). payload and expected come from this image's resources, after the caller checked
   the table. Writes the progress and result lines to the pipe. Returns the exit code it reported (SD_SETUP_EXIT_*). */
DWORD sd_setup_elev_stage2(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                           const sd_setup_args *args, const sd_setup_payload *payload,
                           const unsigned char expected[32]);

/* Stage 2 of a per-machine uninstall (04 §6.7): no payload. It finds the ShellDrive product code in the machine registry
   and runs "msiexec /x <code>" in the stage folder, with the forwarded switches and the msi.log of the stage (sent over the
   pipe as for an install). Returns the exit code it reported. */
DWORD sd_setup_elev_stage2_uninstall(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                                     const sd_setup_args *args);

/* After an all-users install, the parent only (never the elevated stage): starts <machine install folder>\shelldrive-ui.exe
   as the logged-on user. Returns 0 when started; 1 when the folder is unknown, the parent holds an administrator token
   (the UI would run elevated, so it is not started) or the start failed. */
int sd_setup_elev_launch_installed(const sd_setup_elev_ops *ops);

#endif /* SD_SETUP_ELEVATE_H */
