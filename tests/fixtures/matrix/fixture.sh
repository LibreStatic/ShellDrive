#!/bin/sh
# M2 interop fixture set: several private sshd instances and test proxies inside WSL (decisions.md D21: test
# infrastructure only; nothing of it ships). Everything runs as the calling WSL user, never as root; the
# system sshd, /etc/ssh and ~/.ssh are not touched. See README.md and docs/dev/m2-notes.md.
#
#   fixture.sh start  [instance...]   start (idempotent; default: every instance and proxy)
#   fixture.sh stop   [instance...] [--purge]
#   fixture.sh status
#   fixture.sh env                    rewrite state/endpoints.env from what is running
#   fixture.sh rotate a|ab|ba|b       host keys of the "rotate" instance (A only, A+B, B+A, B only), restart it
#   fixture.sh otp-code [offset]      current TOTP of the "otp" instance (offset in 30 s steps)
#   fixture.sh otp-pam                print the one-time sudo commands that enable the "otp" instance
#   fixture.sh kill|drop|freeze|thaw|reap|restart <instance>   fault injection (../wsl-sshd/ctl.sh)
#
# Windows: tests\fixtures\matrix\ctl.ps1 <same arguments>
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE_WIN="$HERE/state"
FIX="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-fixtures"
KEYS="$FIX/keys"
OSSH10="$FIX/openssh10"
SSHD96=/usr/sbin/sshd
USER_NAME="$(id -un)"
KEY_PASS="shelldrive-test-pass"
PROXY_USER="sdproxy"
PROXY_PASS="shelldrive-proxy-pass"
OTP_PAM_SERVICE="shelldrive-otp"

SSHD_INSTANCES="ossh10 ossh10pq legacy legacy3des bastion1 bastion2 target cert rotate otp"
PROXY_INSTANCES="http http-auth socks5 socks5-auth squid dante"

port_of() {
  case "$1" in
    modern) echo 2222 ;; ossh10) echo 2230 ;; legacy) echo 2231 ;; bastion1) echo 2232 ;;
    bastion2) echo 2233 ;; target) echo 2234 ;; cert) echo 2235 ;; rotate) echo 2236 ;; otp) echo 2237 ;;
    legacy3des) echo 2238 ;; ossh10pq) echo 2239 ;;
    http) echo 2280 ;; http-auth) echo 2281 ;; squid) echo 2282 ;;
    socks5) echo 2290 ;; socks5-auth) echo 2291 ;; dante) echo 2292 ;;
    *) echo "unknown instance: $1" >&2; return 1 ;;
  esac
}

# "10" = own OpenSSH 10.x build, "96" = Ubuntu's OpenSSH 9.6p1
flavour_of() {
  case "$1" in ossh10|ossh10pq|bastion2|target|rotate) echo 10 ;; *) echo 96 ;; esac
}

internal_only() { case "$1" in bastion2|target) return 0 ;; *) return 1 ;; esac; }

is_proxy() { case " $PROXY_INSTANCES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

direct_addr() {
  if [ "${SD_SSHD_DIRECT:-1}" != "0" ] && command -v wslinfo >/dev/null 2>&1 &&
     [ "$(wslinfo --networking-mode 2>/dev/null || true)" = "nat" ]; then
    ip -4 -o addr show dev eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1
  fi
}
DIRECT="$(direct_addr)"
WIN_HOST="${DIRECT:-127.0.0.1}"

pidfile_of() { if is_proxy "$1"; then echo "$FIX/proxy-$1/pid"; else echo "$FIX/$1/sshd.pid"; fi; }

running() {
  pf="$(pidfile_of "$1")"
  [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null
}

wait_listen() {   # port addr
  i=0
  while [ $i -lt 50 ]; do
    if ss -Hltn "sport = :$1" 2>/dev/null | grep -q "$2:$1"; then return 0; fi
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

wait_free() {     # port
  i=0
  while [ $i -lt 50 ]; do
    ss -Hltn "sport = :$1" 2>/dev/null | grep -q . || return 0
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

hostkey() {       # type file [bits]
  [ -f "$2" ] && return 0
  if [ -n "${3:-}" ]; then ssh-keygen -q -t "$1" -b "$3" -N '' -C "shelldrive-fixture-host" -f "$2"
  else ssh-keygen -q -t "$1" -N '' -C "shelldrive-fixture-host" -f "$2"; fi
}

# ---------------------------------------------------------------- client keys, CAs, certificates
ensure_keys() {
  mkdir -p "$KEYS" "$STATE_WIN"; chmod 700 "$FIX" "$KEYS"
  k="$KEYS"
  [ -f "$k/client_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C sd-it-ed25519 -f "$k/client_ed25519"
  [ -f "$k/client_ecdsa" ] || ssh-keygen -q -t ecdsa -b 256 -N '' -C sd-it-ecdsa -f "$k/client_ecdsa"
  [ -f "$k/client_rsa" ] || ssh-keygen -q -t rsa -b 3072 -N '' -C sd-it-rsa -f "$k/client_rsa"
  [ -f "$k/client_ed25519_enc" ] || ssh-keygen -q -t ed25519 -N "$KEY_PASS" -C sd-it-ed25519-enc -f "$k/client_ed25519_enc"
  # unencrypted PPK v3 / v2 of the same keys (own converter; encrypted PPK needs puttygen, see README.md)
  [ -f "$k/client_ed25519.ppk" ] || python3 -I "$HERE/ppk.py" "$k/client_ed25519" "$k/client_ed25519.ppk"
  [ -f "$k/client_rsa.ppk" ] || python3 -I "$HERE/ppk.py" "$k/client_rsa" "$k/client_rsa.ppk"
  [ -f "$k/client_ecdsa.ppk" ] || python3 -I "$HERE/ppk.py" "$k/client_ecdsa" "$k/client_ecdsa.ppk"
  [ -f "$k/client_ed25519_v2.ppk" ] || python3 -I "$HERE/ppk.py" --v2 "$k/client_ed25519" "$k/client_ed25519_v2.ppk"
  if command -v puttygen >/dev/null 2>&1 && [ ! -f "$k/client_ed25519_argon2id.ppk" ]; then
    printf '%s\n' "$KEY_PASS" > "$k/.pp"
    puttygen "$k/client_ed25519" -O private -o "$k/client_ed25519_argon2id.ppk" --new-passphrase "$k/.pp" \
      --ppk-param version=3,kdf=argon2id >/dev/null 2>&1 || true
    puttygen "$k/client_rsa" -O private -o "$k/client_rsa_v2_aes.ppk" --new-passphrase "$k/.pp" \
      --ppk-param version=2 >/dev/null 2>&1 || true
    rm -f "$k/.pp"
  fi
  # CAs and certificates (cert instance)
  [ -f "$k/user_ca" ] || ssh-keygen -q -t ed25519 -N '' -C sd-it-user-ca -f "$k/user_ca"
  [ -f "$k/host_ca" ] || ssh-keygen -q -t ed25519 -N '' -C sd-it-host-ca -f "$k/host_ca"
  for name in expired wrongprinc revoked; do
    [ -f "$k/client_$name" ] || ssh-keygen -q -t ed25519 -N '' -C "sd-it-$name" -f "$k/client_$name"
  done
  if [ ! -f "$k/client_ed25519-cert.pub" ]; then
    ssh-keygen -q -s "$k/user_ca" -I sd-it-ed25519 -n "$USER_NAME" -V -5m:+3650d -z 1 "$k/client_ed25519.pub"
    ssh-keygen -q -s "$k/user_ca" -I sd-it-rsa -n "$USER_NAME" -V -5m:+3650d -z 2 "$k/client_rsa.pub"
    ssh-keygen -q -s "$k/user_ca" -I sd-it-ecdsa -n "$USER_NAME" -V -5m:+3650d -z 3 "$k/client_ecdsa.pub"
    ssh-keygen -q -s "$k/user_ca" -I sd-it-expired -n "$USER_NAME" -V 20200101:20200102 -z 4 "$k/client_expired.pub"
    ssh-keygen -q -s "$k/user_ca" -I sd-it-wrongprinc -n nobody-here -V -5m:+3650d -z 5 "$k/client_wrongprinc.pub"
    ssh-keygen -q -s "$k/user_ca" -I sd-it-revoked -n "$USER_NAME" -V -5m:+3650d -z 6 "$k/client_revoked.pub"
    rm -f "$k/revoked.krl"
  fi
  # KRL revoking certificate serial 6 (client_revoked) of the user CA
  if ssh-keygen -Q -f "$k/revoked.krl" "$k/client_revoked-cert.pub" 2>/dev/null | grep -q REVOKED; then :; else
    printf 'serial: 6
' > "$k/revoked.spec"
    ssh-keygen -q -k -f "$k/revoked.krl" -s "$k/user_ca.pub" "$k/revoked.spec" 2>/dev/null
  fi
  # authorized_keys: the fixture's keys plus the M1 fixture's keys, so old tests can log in everywhere
  {
    for p in client_ed25519 client_ecdsa client_rsa client_ed25519_enc; do cat "$k/$p.pub"; done
    M1="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-wsl-sshd"
    for p in client_ed25519 client_ed25519_enc; do [ -f "$M1/$p.pub" ] && cat "$M1/$p.pub"; done
    true
  } > "$k/authorized_keys"
  chmod 600 "$k"/client_* "$k/user_ca" "$k/host_ca" "$k/authorized_keys" 2>/dev/null || true
  chmod 644 "$k"/*.pub
  # client material for the Windows tests
  for f in client_ed25519 client_ecdsa client_rsa client_ed25519_enc client_expired client_wrongprinc \
           client_revoked; do
    cp "$k/$f" "$k/$f.pub" "$STATE_WIN/"
    [ -f "$k/$f-cert.pub" ] && cp "$k/$f-cert.pub" "$STATE_WIN/"
  done
  cp "$k"/*.ppk "$k/user_ca.pub" "$k/host_ca.pub" "$STATE_WIN/"
}

# ---------------------------------------------------------------- sshd instances
listen_lines() {
  if internal_only "$1"; then echo "ListenAddress 127.0.0.2"
  else
    echo "ListenAddress 127.0.0.1"
    [ -n "$DIRECT" ] && echo "ListenAddress $DIRECT"
  fi
  true
}

host_keys() {     # instance dir -> HostKey lines; generates the keys
  d="$2"
  case "$1" in
    legacy|legacy3des)
      hostkey rsa "$d/host_rsa" 2048
      echo "HostKey $d/host_rsa"
      if [ "$1" = legacy ]; then hostkey dsa "$d/host_dsa"; echo "HostKey $d/host_dsa"; fi ;;
    ossh10|ossh10pq)
      hostkey ed25519 "$d/host_ed25519"; hostkey ecdsa "$d/host_ecdsa" 256; hostkey rsa "$d/host_rsa" 3072
      printf 'HostKey %s\nHostKey %s\nHostKey %s\n' "$d/host_ed25519" "$d/host_ecdsa" "$d/host_rsa" ;;
    rotate)
      hostkey ed25519 "$d/host_a"; hostkey ed25519 "$d/host_b"
      mode="$(cat "$d/mode" 2>/dev/null || echo a)"
      case "$mode" in
        a) echo "HostKey $d/host_a" ;;
        b) echo "HostKey $d/host_b" ;;
        ab) printf 'HostKey %s\nHostKey %s\n' "$d/host_a" "$d/host_b" ;;
        ba) printf 'HostKey %s\nHostKey %s\n' "$d/host_b" "$d/host_a" ;;
      esac ;;
    cert)
      hostkey ed25519 "$d/host_ed25519"
      if [ ! -f "$d/host_ed25519-cert.pub" ] || [ "$(cat "$d/cert_principals" 2>/dev/null)" != "${DIRECT:-}" ]; then
        ssh-keygen -q -s "$KEYS/host_ca" -h -I sd-it-cert-host -n "127.0.0.1,localhost${DIRECT:+,$DIRECT}" \
          -V -5m:+3650d "$d/host_ed25519.pub"
        echo "${DIRECT:-}" > "$d/cert_principals"
      fi
      printf 'HostKey %s\nHostCertificate %s\n' "$d/host_ed25519" "$d/host_ed25519-cert.pub" ;;
    *)
      hostkey ed25519 "$d/host_ed25519"; hostkey ecdsa "$d/host_ecdsa" 256
      printf 'HostKey %s\nHostKey %s\n' "$d/host_ed25519" "$d/host_ecdsa" ;;
  esac
}

extra_config() {
  case "$1" in
    ossh10)
      echo "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256" ;;
    ossh10pq)
      echo "KexAlgorithms mlkem768x25519-sha256" ;;
    legacy)
      echo "KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256"
      echo "Ciphers 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc"
      echo "MACs hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96"
      echo "HostKeyAlgorithms ssh-rsa,ssh-dss"
      echo "PubkeyAcceptedAlgorithms ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-ed25519,ecdsa-sha2-nistp256" ;;
    legacy3des)
      echo "KexAlgorithms diffie-hellman-group14-sha1"
      echo "Ciphers 3des-cbc"
      echo "MACs hmac-sha1"
      echo "HostKeyAlgorithms ssh-rsa"
      echo "PubkeyAcceptedAlgorithms ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-ed25519,ecdsa-sha2-nistp256" ;;
    bastion1|bastion2|otp)
      echo "AllowTcpForwarding local"
      echo "PermitOpen 127.0.0.1:* 127.0.0.2:*" ;;
    cert)
      echo "AuthorizedKeysFile none"
      echo "TrustedUserCAKeys $KEYS/user_ca.pub"
      echo "RevokedKeys $KEYS/revoked.krl" ;;
  esac
  case "$1" in bastion1|bastion2|otp) ;; *) echo "AllowTcpForwarding no" ;; esac
  if [ "$1" = otp ]; then
    echo "UsePAM yes"
    echo "KbdInteractiveAuthentication yes"
    echo "AuthenticationMethods ${SD_OTP_METHODS:-publickey,keyboard-interactive}"
  else
    # the own 10.x build has no PAM support at all (the option would be rejected)
    [ "$(flavour_of "$1")" = 10 ] || echo "UsePAM no"
    echo "KbdInteractiveAuthentication no"
  fi
  # OpenSSH >= 9.8 penalises sources after failed logins; negative tests would lock themselves out
  [ "$(flavour_of "$1")" = 10 ] && echo "PerSourcePenalties no"
  true
}

otp_ready() {
  [ -f "/etc/pam.d/$OTP_PAM_SERVICE" ] && [ -f /usr/lib/x86_64-linux-gnu/security/pam_google_authenticator.so ]
}

otp_secret_file() { echo "$FIX/otp/google_authenticator"; }

ensure_otp_secret() {
  mkdir -p "$FIX/otp"; chmod 700 "$FIX/otp"
  f="$(otp_secret_file)"
  [ -f "$f" ] && return 0
  secret="$(python3 -I -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode())')"
  printf '%s\n" TOTP_AUTH\n" WINDOW_SIZE 3\n' "$secret" > "$f"
  [ -n "${SD_OTP_DISALLOW_REUSE:-}" ] && printf '" DISALLOW_REUSE\n' >> "$f"
  chmod 600 "$f"
}

sshd_binary() {
  case "$(flavour_of "$1")" in
    10) echo "$OSSH10/sbin/sshd" ;;
    *) if [ "$1" = otp ]; then echo "$FIX/bin/$OTP_PAM_SERVICE"; else echo "$SSHD96"; fi ;;
  esac
}

start_sshd() {
  name="$1"; d="$FIX/$name"; port="$(port_of "$name")"
  if running "$name"; then echo "$name: already running (port $port)"; return 0; fi
  bin="$(sshd_binary "$name")"
  if [ "$(flavour_of "$name")" = 10 ] && [ ! -x "$bin" ]; then
    echo "$name: SKIPPED, OpenSSH 10 not built (run tests/fixtures/openssh10/build.sh)"; return 0
  fi
  if [ "$name" = otp ]; then
    if ! otp_ready; then echo "$name: SKIPPED, PAM service not installed (fixture.sh otp-pam)"; return 0; fi
    mkdir -p "$FIX/bin"; ln -sfn "$SSHD96" "$bin"      # PAM service name = program name
    ensure_otp_secret
  fi
  mkdir -p "$d"; chmod 700 "$d"
  {
    echo "# Generated by tests/fixtures/matrix/fixture.sh ($name). Private test instance; not the system sshd."
    echo "Port $port"
    listen_lines "$name"
    host_keys "$name" "$d"
    echo "PidFile $d/sshd.pid"
    [ "$name" = cert ] || echo "AuthorizedKeysFile $KEYS/authorized_keys"
    echo "AllowUsers $USER_NAME"
    echo "PermitRootLogin no"
    echo "PubkeyAuthentication yes"
    echo "PasswordAuthentication no"
    echo "StrictModes no"
    echo "MaxAuthTries 10"
    echo "MaxSessions 10"
    echo "MaxStartups 64:30:128"
    echo "Subsystem sftp internal-sftp"
    echo "LogLevel VERBOSE"
    extra_config "$name"
  } > "$d/sshd_config"
  "$bin" -t -f "$d/sshd_config" || { echo "$name: config test failed ($d/sshd_config)" >&2; return 1; }
  wait_free "$port" || { echo "$name: port $port busy" >&2; return 1; }
  "$bin" -f "$d/sshd_config" -E "$d/sshd.log"
  if internal_only "$name"; then a=127.0.0.2; else a=127.0.0.1; fi
  wait_listen "$port" "$a" || { echo "$name: not listening on $a:$port, see $d/sshd.log" >&2; return 1; }
  echo "$name: listening on port $port ($("$bin" -V 2>&1 | head -n 1 | cut -d, -f1))"
}

stop_one() {
  pf="$(pidfile_of "$1")"
  if [ -f "$pf" ]; then
    p="$(cat "$pf")"
    if kill -0 "$p" 2>/dev/null; then kill "$p" 2>/dev/null || true; echo "$1: stopped (pid $p)"; fi
    rm -f "$pf"
  fi
  wait_free "$(port_of "$1")" || true
}

# ---------------------------------------------------------------- proxies
start_proxy() {
  name="$1"; d="$FIX/proxy-$name"; port="$(port_of "$name")"
  if running "$name"; then echo "$name: already running (port $port)"; return 0; fi
  mkdir -p "$d"
  log="$STATE_WIN/proxy-$name.log"
  listen="--listen 127.0.0.1:$port${DIRECT:+ --listen $DIRECT:$port}"
  case "$name" in
    http) set -- --mode http ;;
    http-auth) set -- --mode http --auth "$PROXY_USER:$PROXY_PASS" ;;
    socks5) set -- --mode socks5 ;;
    socks5-auth) set -- --mode socks5 --auth "$PROXY_USER:$PROXY_PASS" ;;
    squid)
      command -v squid >/dev/null 2>&1 || { echo "squid: SKIPPED, not installed (sudo apt install squid)"; return 0; }
      start_squid "$d" "$port" "$log"; return $? ;;
    dante)
      command -v danted >/dev/null 2>&1 || { echo "dante: SKIPPED, not installed (sudo apt install dante-server)"; return 0; }
      start_dante "$d" "$port" "$log"; return $? ;;
  esac
  wait_free "$port" || { echo "$name: port $port busy" >&2; return 1; }
  # shellcheck disable=SC2086
  nohup python3 -I "$HERE/proxies/proxy.py" "$@" $listen --log "$log" --pidfile "$d/pid" \
    > "$d/stdout.log" 2>&1 < /dev/null &
  wait_listen "$port" 127.0.0.1 || { echo "$name: not listening, see $d/stdout.log" >&2; return 1; }
  echo "$name: listening on port $port (python proxy)"
}

# Squid can run unprivileged with its own config (no cache_dir, pid and logs in $d). Untested here: Squid
# is not installed on the reference machine (needs sudo apt install squid).
start_squid() {
  d="$1"; port="$2"; log="$3"
  printf '%s:%s\n' "$PROXY_USER" "$(openssl passwd -apr1 "$PROXY_PASS")" > "$d/htpasswd"
  cat > "$d/squid.conf" <<CONF
http_port 127.0.0.1:$port
${DIRECT:+http_port $DIRECT:$port}
pid_filename $d/pid
cache_log $d/cache.log
access_log stdio:$log
cache deny all
cache_mem 8 MB
coredump_dir $d
auth_param basic program /usr/lib/squid/basic_ncsa_auth $d/htpasswd
auth_param basic realm shelldrive-test
acl authed proxy_auth REQUIRED
acl fixture_ports port 2222-2299
acl CONNECT method CONNECT
acl fixture_dst dst 127.0.0.0/8${DIRECT:+ $DIRECT}
http_access deny !fixture_ports
http_access deny !fixture_dst
http_access allow CONNECT authed
http_access deny all
CONF
  squid -f "$d/squid.conf" -N -d 1 > "$d/stdout.log" 2>&1 < /dev/null &
  wait_listen "$port" 127.0.0.1 || { echo "squid: not listening, see $d/cache.log" >&2; return 1; }
  echo "squid: listening on port $port (Basic auth $PROXY_USER)"
}

# Dante as non-root: only socksmethod "none" (username auth reads the system password database). Untested
# here: dante-server is not installed on the reference machine (needs sudo apt install dante-server).
start_dante() {
  d="$1"; port="$2"; log="$3"
  {
    echo "logoutput: $log"
    echo "internal: 127.0.0.1 port = $port"
    [ -n "$DIRECT" ] && echo "internal: $DIRECT port = $port"
    echo "external: lo"
    [ -n "$DIRECT" ] && echo "external: eth0"
    echo "clientmethod: none"
    echo "socksmethod: none"
    echo "client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }"
    echo "socks pass { from: 0.0.0.0/0 to: 127.0.0.0/8 port 2222-2299 command: connect }"
    [ -n "$DIRECT" ] && echo "socks pass { from: 0.0.0.0/0 to: $DIRECT/32 port 2222-2299 command: connect }"
    echo "socks block { from: 0.0.0.0/0 to: 0.0.0.0/0 }"
  } > "$d/danted.conf"
  danted -f "$d/danted.conf" -p "$d/pid" -D > "$d/stdout.log" 2>&1 < /dev/null
  wait_listen "$port" 127.0.0.1 || { echo "dante: not listening, see $log" >&2; return 1; }
  echo "dante: listening on port $port (no auth)"
}

# ---------------------------------------------------------------- endpoints.env for the Windows tests
win() { wslpath -w "$1"; }

hostkey_list() {  # instance -> "type b64;type b64"
  d="$FIX/$1"; out=""
  for f in $(sed -n 's/^HostKey //p' "$d/sshd_config" 2>/dev/null); do
    out="${out:+$out;}$(cut -d' ' -f1,2 "$f.pub")"
  done
  echo "$out"
}

kh_names() {      # instance -> known_hosts host pattern
  port="$(port_of "$1")"
  if internal_only "$1"; then echo "[127.0.0.2]:$port"
  else echo "[127.0.0.1]:$port${DIRECT:+,[$DIRECT]:$port}"; fi
}

emit() { printf '%s
' "$*"; }   # echo would interpret the backslashes of Windows paths

write_env() {
  mkdir -p "$STATE_WIN"
  envf="$STATE_WIN/endpoints.env"; kh="$STATE_WIN/known_hosts"
  S="$(win "$STATE_WIN")"
  {
    echo "# Generated by tests/fixtures/matrix/fixture.sh; see docs/dev/m2-notes.md. Windows paths."
    emit "SD_IT_STATE_DIR=$S"
    emit "SD_IT_USER=$USER_NAME"
    emit "SD_IT_DIRECT_HOST=${DIRECT:-}"
    emit "SD_IT_WIN_HOST=$WIN_HOST"
    emit "SD_IT_KNOWN_HOSTS=$S\\known_hosts"
    emit "SD_IT_KEY_PASSPHRASE=$KEY_PASS"
    for f in client_ed25519 client_ecdsa client_rsa client_ed25519_enc; do
      v="$(echo "$f" | sed 's/^client_//' | tr 'a-z' 'A-Z')"
      emit "SD_IT_KEY_$v=$S\\$f"
    done
    emit "SD_IT_KEY_ED25519_PPK3=$S\\client_ed25519.ppk"
    emit "SD_IT_KEY_RSA_PPK3=$S\\client_rsa.ppk"
    emit "SD_IT_KEY_ECDSA_PPK3=$S\\client_ecdsa.ppk"
    emit "SD_IT_KEY_ED25519_PPK2=$S\\client_ed25519_v2.ppk"
    [ -f "$STATE_WIN/client_ed25519_argon2id.ppk" ] && emit "SD_IT_KEY_ED25519_PPK3_ARGON2ID=$S\\client_ed25519_argon2id.ppk"
    [ -f "$STATE_WIN/client_rsa_v2_aes.ppk" ] && emit "SD_IT_KEY_RSA_PPK2_AES=$S\\client_rsa_v2_aes.ppk"
    emit "SD_IT_USER_CA=$(cut -d' ' -f1,2 "$KEYS/user_ca.pub")"
    emit "SD_IT_HOST_CA=$(cut -d' ' -f1,2 "$KEYS/host_ca.pub")"
    for f in ed25519 rsa ecdsa expired wrongprinc revoked; do
      v="$(echo "$f" | tr 'a-z' 'A-Z')"
      emit "SD_IT_CERT_$v=$S\\client_$f-cert.pub"
      [ "$f" = ed25519 ] || [ "$f" = rsa ] || [ "$f" = ecdsa ] || emit "SD_IT_CERT_${v}_KEY=$S\\client_$f"
    done
    for n in modern $SSHD_INSTANCES; do
      u="$(echo "$n" | tr 'a-z' 'A-Z')"
      if [ "$n" = modern ]; then
        [ -f "$HERE/../wsl-sshd/state/env" ] || continue
        emit "SD_IT_MODERN_HOST=$WIN_HOST"
        emit "SD_IT_MODERN_PORT=2222"
        emit "SD_IT_MODERN_HOSTKEYS=$(sed -n 's/^hostkey=//p' "$HERE/../wsl-sshd/state/env")"
        continue
      fi
      running "$n" || continue
      if internal_only "$n"; then emit "SD_IT_${u}_HOST=127.0.0.2"; else emit "SD_IT_${u}_HOST=$WIN_HOST"; fi
      emit "SD_IT_${u}_PORT=$(port_of "$n")"
      emit "SD_IT_${u}_HOSTKEYS=$(hostkey_list "$n")"
    done
    if running rotate; then
      emit "SD_IT_ROTATE_MODE=$(cat "$FIX/rotate/mode" 2>/dev/null || echo a)"
      emit "SD_IT_ROTATE_HOSTKEY_A=$(cut -d' ' -f1,2 "$FIX/rotate/host_a.pub")"
      emit "SD_IT_ROTATE_HOSTKEY_B=$(cut -d' ' -f1,2 "$FIX/rotate/host_b.pub")"
    fi
    if running otp; then
      emit "SD_IT_OTP_SECRET=$(head -n 1 "$(otp_secret_file)")"
      emit "SD_IT_OTP_METHODS=${SD_OTP_METHODS:-publickey,keyboard-interactive}"
    fi
    emit "SD_IT_PROXY_USER=$PROXY_USER"
    emit "SD_IT_PROXY_PASS=$PROXY_PASS"
    for n in $PROXY_INSTANCES; do
      running "$n" || continue
      u="$(echo "$n" | tr 'a-z-' 'A-Z_')"
      emit "SD_IT_PROXY_${u}=$WIN_HOST:$(port_of "$n")"
      emit "SD_IT_PROXY_${u}_LOG=$S\\proxy-$n.log"
    done
    emit "SD_IT_FIXTURE_SH=$HERE/fixture.sh"
  } > "$envf"
  {
    echo "# Generated by tests/fixtures/matrix/fixture.sh. The rotate instance is listed with key A only."
    if [ -f "$HERE/../wsl-sshd/state/env" ]; then
      echo "[127.0.0.1]:2222${DIRECT:+,[$DIRECT]:2222} $(sed -n 's/^hostkey=//p' "$HERE/../wsl-sshd/state/env")"
    fi
    for n in $SSHD_INSTANCES; do
      running "$n" || continue
      if [ "$n" = rotate ]; then
        echo "$(kh_names rotate) $(cut -d' ' -f1,2 "$FIX/rotate/host_a.pub")"; continue
      fi
      hostkey_list "$n" | tr ';' '\n' | while read -r line; do echo "$(kh_names "$n") $line"; done
    done
    running cert && echo "@cert-authority $(kh_names cert) $(cut -d' ' -f1,2 "$KEYS/host_ca.pub")"
    true
  } > "$kh"
}

# ---------------------------------------------------------------- commands
start_all() {
  ensure_keys
  list="$*"; [ -n "$list" ] || list="$SSHD_INSTANCES $PROXY_INSTANCES"
  rc=0
  for n in $list; do
    port_of "$n" >/dev/null || { rc=2; continue; }
    if is_proxy "$n"; then start_proxy "$n" || rc=1; else start_sshd "$n" || rc=1; fi
  done
  write_env
  echo "endpoints: $STATE_WIN/endpoints.env"
  return $rc
}

stop_all() {
  purge=""; list=""
  for a in "$@"; do if [ "$a" = --purge ]; then purge=1; else list="$list $a"; fi; done
  [ -n "$list" ] || list="$SSHD_INSTANCES $PROXY_INSTANCES"
  for n in $list; do port_of "$n" >/dev/null && stop_one "$n"; done
  if [ -n "$purge" ]; then
    for n in $SSHD_INSTANCES; do rm -rf "${FIX:?}/$n"; done
    for n in $PROXY_INSTANCES; do rm -rf "${FIX:?}/proxy-$n"; done
    rm -rf "${FIX:?}/keys" "${FIX:?}/otp" "${FIX:?}/bin" "$STATE_WIN"
    echo "purged fixture state (the OpenSSH 10 build in $FIX stays)"
  elif [ -d "$STATE_WIN" ]; then
    write_env
  fi
}

status_all() {
  for n in $SSHD_INSTANCES $PROXY_INSTANCES; do
    if running "$n"; then echo "$n: running (pid $(cat "$(pidfile_of "$n")"), port $(port_of "$n"))"
    else echo "$n: stopped"; fi
  done
}

cmd="${1:-status}"; [ $# -gt 0 ] && shift
case "$cmd" in
  start) start_all "$@" ;;
  stop) stop_all "$@" ;;
  status) status_all ;;
  env) write_env; echo "$STATE_WIN/endpoints.env" ;;
  rotate)
    mode="${1:-}"
    case "$mode" in a|ab|ba|b) ;; *) echo "usage: fixture.sh rotate a|ab|ba|b" >&2; exit 2 ;; esac
    mkdir -p "$FIX/rotate"; echo "$mode" > "$FIX/rotate/mode"
    stop_one rotate >/dev/null
    start_sshd rotate
    write_env ;;
  otp-code)
    f="$(otp_secret_file)"; [ -f "$f" ] || { echo "otp secret not generated yet (start the otp instance)" >&2; exit 1; }
    python3 -I - "$(head -n 1 "$f")" "${1:-0}" <<'PY'
import base64, hmac, struct, sys, time
key = base64.b32decode(sys.argv[1])
c = int(time.time()) // 30 + int(sys.argv[2])
h = hmac.new(key, struct.pack(">Q", c), "sha1").digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000))
PY
    ;;
  otp-pam)
    cat <<EOF
# One-time setup for the "otp" fixture instance (port 2237). The sshd itself still runs as $USER_NAME;
# root is only needed to install the PAM module and to create its PAM service file.
sudo apt install libpam-google-authenticator
sudo tee /etc/pam.d/$OTP_PAM_SERVICE >/dev/null <<'PAM'
# ShellDrive interop fixture (test only): TOTP for the unprivileged sshd started by
# tests/fixtures/matrix/fixture.sh. Not used by the system sshd.
auth     required pam_google_authenticator.so secret=\${HOME}/.local/state/shelldrive-fixtures/otp/google_authenticator
account  required pam_permit.so
session  required pam_permit.so
password required pam_deny.so
PAM
# then: sh tests/fixtures/matrix/fixture.sh start otp
# undo: sudo rm /etc/pam.d/$OTP_PAM_SERVICE && sudo apt remove libpam-google-authenticator
EOF
    ;;
  kill|drop|freeze|thaw|reap|restart)
    [ $# -ge 1 ] || { echo "usage: fixture.sh $cmd <instance>" >&2; exit 2; }
    sh "$HERE/../wsl-sshd/ctl.sh" "$cmd" "$1" ;;
  *)
    echo "usage: fixture.sh start|stop|status|env|rotate|otp-code|otp-pam|kill|drop|freeze|thaw|reap|restart" >&2
    exit 2 ;;
esac
