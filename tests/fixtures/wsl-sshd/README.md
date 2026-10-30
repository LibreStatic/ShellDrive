# WSL sshd interop fixture

A private OpenSSH server inside WSL (Ubuntu 24.04) for the `interop` CTest label. Test infrastructure
only (decisions.md D21); nothing here ships.

- Runs as the calling WSL user, never as root, on `127.0.0.1:2222` (`SD_SSHD_PORT` overrides it).
  In WSL's NAT networking mode it also listens on the VM's `eth0` address (reachable from the Windows
  host only) and writes it to `state/env` as `direct_host`; the interop tests prefer it, because the
  localhost relay (`wslrelay`) can wedge for a port when sshd is killed during heavy traffic.
  `SD_SSHD_DIRECT=0` (start) turns it off; `SD_SSHD_VIA_RELAY=1` (tests) forces `127.0.0.1`.
- Own `sshd_config`, host key, client keys and `authorized_keys` under
  `~/.local/state/shelldrive-wsl-sshd/` inside WSL. The system sshd, `/etc/ssh` and the user's
  `~/.ssh` are not touched, and no `sudo` is needed (only `openssh-server` must be installed; its
  service can stay disabled).
- The client keys and an `env` file for the Windows tests are copied to `state/` here (gitignored).
- `RekeyLimit 4M` makes the server initiate rekeys during the bulk test.

## Use

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\start.ps1   # -Distro <name> optional
& $ctest --test-dir build\<dir> -C Release -L interop
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\stop.ps1    # -Purge deletes keys
```

From WSL directly: `sh tests/fixtures/wsl-sshd/start.sh` / `stop.sh [--purge]`.

`interop.ssh` (`sd-test-ssh-interop.exe`) exits with 77, reported by CTest as *Skipped*, when
`state/env` is missing or nothing listens on the port. The fixture
directory can be overridden with the environment variable `SD_SSH_WSL_FIXTURE_DIR`.

## Password and keyboard-interactive logins

A non-root sshd cannot verify passwords (no access to `/etc/shadow`, no PAM), so the fixture
disables both methods and the automated tests use public keys only. To test password logins by
hand, run a second instance as root on another port, without touching the system service:

```sh
sudo /usr/sbin/sshd -D -p 2223 -o ListenAddress=127.0.0.1 -o UsePAM=yes \
  -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes \
  -o PidFile=/tmp/sd-sshd-2223.pid -o Subsystem="sftp internal-sftp"
```

(`/run/sshd` must exist: `sudo mkdir -p /run/sshd`.) Connect to `127.0.0.1:2223` with the WSL
account password and stop the instance with Ctrl+C.

## Fault injection (M1 resilience tests)

`ctl.sh` (or `ctl.ps1 <command>` from Windows) breaks the running fixture on purpose:
`kill` (listener and every session process, like a crash; keys stay), `start`, `restart`, `drop` (session
processes only: established connections drop, new ones are accepted), `freeze` / `thaw` / `reap`
(SIGSTOP / SIGCONT / kill the session processes: a silent link), `status`. Only the fixture's own
processes are touched. `interop.sftp_ssh` uses it and starts the fixture again at the end.
An optional second argument (`ctl.sh drop ossh10`, `ctl.ps1 kill -Instance bastion1`) applies the same commands to
an M2 fixture instance (`tests/fixtures/matrix/README.md`); without it this fixture is meant, as before.
