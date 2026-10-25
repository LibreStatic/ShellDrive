# M2 interop fixture set (WSL)

Several private sshd instances and test proxies inside WSL Ubuntu 24.04, for the M2 interop matrix
(`tests/interop/run-matrix.ps1`). Test infrastructure only (decisions.md D21): everything runs as the WSL user,
never as root; the system sshd, `/etc/ssh`, `~/.ssh` are not touched; nothing of it ships.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\openssh10\build.ps1   # once
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\matrix\ctl.ps1 start  # idempotent
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\matrix\ctl.ps1 selftest
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\matrix\ctl.ps1 stop   # [--purge]
```

`ctl.ps1` passes its arguments to `fixture.sh` (`start|stop [instance...]`, `status`, `env`, `rotate a|ab|ba|b`,
`otp-code [offset]`, `otp-pam`, `kill|drop|freeze|thaw|reap|restart <instance>`) and `selftest` to `selftest.sh`.

## Files

| Path | What |
|------|------|
| `fixture.sh` | generates keys, CAs, certificates, configs; starts/stops instances; writes `state/endpoints.env` and `state/known_hosts` |
| `selftest.sh` | proves every instance with the stock OpenSSH 9.6 / 10.x clients (about 10 s, ~53 checks) |
| `proxies/proxy.py` | HTTP CONNECT (Basic auth optional) and SOCKS5 (RFC 1929 optional) proxy, Python stdlib |
| `proxies/probe.py` | the client side of both proxies; usable as an OpenSSH `ProxyCommand` |
| `ppk.py` | unencrypted PPK v3/v2 writer from an OpenSSH key (stdlib; encrypted PPK needs puttygen) |
| `state/` (gitignored) | client keys, PPKs, certificates, CA public keys, `known_hosts`, `endpoints.env`, proxy logs |

Server-side state: `~/.local/state/shelldrive-fixtures/<instance>/` (config, host keys, `sshd.log`, pid) and
`.../keys/` (client keys, CAs, `authorized_keys`, KRL).

## Instances

Listen on `127.0.0.1` and the WSL NAT address (`SD_IT_WIN_HOST` / `direct_host`), except `bastion2` and `target`,
which listen on `127.0.0.2` inside WSL only: they are reachable only through a jump host or a proxy.

| Instance | Port | Binary | Configuration |
|----------|------|--------|---------------|
| `ossh10` | 2230 | 10.6p1 | KEX list starts with `mlkem768x25519-sha256`; host keys ed25519, ECDSA P-256, RSA-3072 |
| `ossh10pq` | 2239 | 10.6p1 | `KexAlgorithms mlkem768x25519-sha256` only |
| `legacy` | 2231 | 9.6p1 | only legacy: dh-group1-sha1, dh-group14-sha1, dh-gex-sha1, dh-gex-sha256; 3des-cbc, aes128/192/256-cbc; hmac-sha1, hmac-sha1-96, hmac-md5, hmac-md5-96; host keys ssh-rsa (SHA-1 signatures, RSA-2048) and ssh-dss (1024); user keys ssh-rsa (SHA-1) accepted |
| `legacy3des` | 2238 | 9.6p1 | exactly one choice each: diffie-hellman-group14-sha1, 3des-cbc, hmac-sha1, ssh-rsa |
| `bastion1` | 2232 | 9.6p1 | `AllowTcpForwarding local`, `PermitOpen 127.0.0.1:* 127.0.0.2:*` |
| `bastion2` | 127.0.0.2:2233 | 10.6p1 | same forwarding rules (second hop of 3-hop chains) |
| `target` | 127.0.0.2:2234 | 10.6p1 | normal key login; ed25519 + ECDSA host keys |
| `cert` | 2235 | 9.6p1 | `AuthorizedKeysFile none`, `TrustedUserCAKeys` (user CA), `RevokedKeys` (KRL with serial 6), `HostCertificate` from the host CA, principals `127.0.0.1,localhost,<direct_host>` |
| `rotate` | 2236 | 10.6p1 | host keys A and B (both ed25519) selected by `fixture.sh rotate a|ab|ba|b` (restarts the instance) |
| `otp` | 2237 | 9.6p1 + PAM | `AuthenticationMethods publickey,keyboard-interactive` (TOTP via pam_google_authenticator), bastion forwarding rules; **needs the one-time sudo step below** |
| `http` / `http-auth` | 2280 / 2281 | Python | CONNECT; Basic auth `sdproxy` / `shelldrive-proxy-pass` on 2281 (407 + retry on the same connection) |
| `socks5` / `socks5-auth` | 2290 / 2291 | Python | CONNECT, ATYP IPv4/domain/IPv6; 2291 offers only method 02 (RFC 1929), same credentials |
| `squid` / `dante` | 2282 / 2292 | Squid / Dante | started only if installed (`sudo apt install squid dante-server`); configs in `fixture.sh`, **untested** here. Dante as non-root supports only `socksmethod: none` |

9.6p1 can still enable every legacy algorithm requested for M2 (3des-cbc, aes-cbc, hmac-sha1/md5, ssh-rsa with
SHA-1, ssh-dss, dh-group1/14-sha1, both GEX variants); none of them is compiled out in Ubuntu's build. 10.x no
longer has ssh-dss, so the legacy instances stay on 9.6.

Every instance (except `cert`) accepts the fixture keys (`client_ed25519`, `client_ecdsa`, `client_rsa`,
`client_ed25519_enc` with passphrase `shelldrive-test-pass`) and the M1 fixture's keys. The PPK files are the same
keys (`client_ed25519.ppk` / `client_rsa.ppk` / `client_ecdsa.ppk` are PPK v3 `Encryption: none`,
`client_ed25519_v2.ppk` is v2), written by `ppk.py`; with puttygen installed `fixture.sh` also writes
`client_ed25519_argon2id.ppk` (v3, Argon2id, passphrase as above) and `client_rsa_v2_aes.ppk`.

Certificates (user CA `user_ca.pub`): `client_{ed25519,rsa,ecdsa}-cert.pub` valid for the WSL user (serials 1-3),
`client_expired-cert.pub` (2020-01-01..02), `client_wrongprinc-cert.pub` (principal `nobody-here`),
`client_revoked-cert.pub` (serial 6, in the KRL). Each of the last three has its own key `client_<name>`.

Proxies only connect to loopback and this machine's own addresses (HTTP 403 / SOCKS reply 02 otherwise) and log one
line per request to `state/proxy-<name>.log`, so a test can prove the proxy was used.

## OTP (keyboard-interactive) instance: one-time sudo step

A non-root sshd can run PAM, but the PAM module and its service file need root once. The sshd still runs as the
WSL user; the PAM service name is the program name, so `fixture.sh` starts it through a symlink named
`shelldrive-otp` and nothing else (the system sshd included) uses that service. `fixture.sh otp-pam` prints:

```sh
sudo apt install libpam-google-authenticator
sudo tee /etc/pam.d/shelldrive-otp >/dev/null <<'PAM'
auth     required pam_google_authenticator.so secret=${HOME}/.local/state/shelldrive-fixtures/otp/google_authenticator
account  required pam_permit.so
session  required pam_permit.so
password required pam_deny.so
PAM
```

Then `fixture.sh start otp`. The TOTP secret (base32) is `SD_IT_OTP_SECRET`; `fixture.sh otp-code` prints the
current code. `SD_OTP_DISALLOW_REUSE=1` (when the secret is first created) makes each code single-use;
`SD_OTP_METHODS` overrides `AuthenticationMethods`. Verified without the module: the unprivileged sshd starts the
PAM keyboard-interactive device; the full login is not verified until the sudo step is done.

## Fault injection

`../wsl-sshd/ctl.sh <kill|drop|freeze|thaw|reap|restart|status> <instance>` (or `ctl.ps1 <cmd> -Instance <name>`)
works on any instance here. A proxy is a single process (the "listener", no session processes), so only `kill`,
`restart` and `status` act on it; `drop`/`freeze`/`thaw`/`reap` find nothing to signal.
