#!/bin/sh
# Self-test of the M2 fixtures with the stock OpenSSH clients inside WSL (9.6 system client, 10.x own build):
# proves each instance offers what README.md promises, before any ShellDrive test relies on it.
# Prints "PASS <check>" / "FAIL <check>" / "SKIP <check> (reason)" lines; exit status 1 if anything failed.
#   sh tests/fixtures/matrix/selftest.sh        (after fixture.sh start)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
FIX="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-fixtures"
K="$FIX/keys"
U="$(id -un)"
SSH96=/usr/bin/ssh
SSH10="$FIX/openssh10/bin/ssh"
T="$FIX/selftest"
rm -rf "$T"; mkdir -p "$T"; chmod 700 "$T"
cp "$HERE/state/known_hosts" "$T/kh"
# one client config for every hop: ProxyJump passes -F on to the jump ssh processes
cat > "$T/cfg" <<CFG
Host *
  BatchMode yes
  StrictHostKeyChecking yes
  UserKnownHostsFile $T/kh
  IdentitiesOnly yes
  ConnectTimeout 10
CFG
# the jump hops need a key too (-i is not passed on); a separate file so that no other check offers it
{ cat "$T/cfg"; echo "  IdentityFile $K/client_ed25519"; } > "$T/cfgj"
CFG="$T/cfg"
FAILS=0

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
skip() { echo "SKIP $1 ($2)"; }
running() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }
up() { running "$FIX/$1/sshd.pid"; }

# ssh_run <client> <port> <host> <extra opts...> ; output in $T/out
ssh_run() {
  c="$1"; p="$2"; h="$3"; shift 3
  timeout 60 "$c" -F "$CFG" -v -p "$p" "$@" "$U@$h" true > "$T/out" 2>&1 < /dev/null
}
kex_is() { tr -d '\r' < "$T/out" | grep -q "kex: algorithm: $1\$"; }   # ssh -v ends lines with CR LF
expect_ok() { name="$1"; shift; if ssh_run "$@"; then pass "$name"; else fail "$name"; sed 's/^/    /' "$T/out" | tail -5; fi; }
expect_fail() { name="$1"; shift; if ssh_run "$@"; then fail "$name (login succeeded)"; else pass "$name"; fi; }

ED="-i $K/client_ed25519"
RSA="-i $K/client_rsa"

# ---- ossh10 / ossh10pq
if up ossh10 && [ -x "$SSH10" ]; then
  if ssh_run "$SSH10" 2230 127.0.0.1 $ED && kex_is mlkem768x25519-sha256; then pass "ossh10.kex_mlkem768x25519"; else fail "ossh10.kex_mlkem768x25519"; fi
  expect_ok "ossh10.rsa_hostkey_rsa-sha2-512" "$SSH10" 2230 127.0.0.1 $ED -o HostKeyAlgorithms=rsa-sha2-512
  expect_ok "ossh10.ecdsa_hostkey" "$SSH10" 2230 127.0.0.1 $ED -o HostKeyAlgorithms=ecdsa-sha2-nistp256
  expect_ok "ossh10.client_9.6_falls_back" "$SSH96" 2230 127.0.0.1 $ED
  expect_ok "ossh10.ppk_keys_authorized(rsa)" "$SSH10" 2230 127.0.0.1 $RSA
else skip ossh10 "not running or not built"; fi
if up ossh10pq; then
  if ssh_run "$SSH10" 2239 127.0.0.1 $ED && kex_is mlkem768x25519-sha256; then pass "ossh10pq.kex_mlkem768x25519"; else fail "ossh10pq.kex_mlkem768x25519"; fi
  expect_fail "ossh10pq.refuses_non_pq_client(9.6)" "$SSH96" 2239 127.0.0.1 $ED
else skip ossh10pq "not running"; fi

# ---- legacy
if up legacy; then
  L="-o Ciphers=+3des-cbc,aes128-cbc,aes256-cbc -o MACs=+hmac-sha1,hmac-md5 -o HostKeyAlgorithms=+ssh-rsa,ssh-dss -o PubkeyAcceptedAlgorithms=+ssh-rsa"
  expect_fail "legacy.refuses_default_client" "$SSH96" 2231 127.0.0.1 $RSA
  for kex in diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1 diffie-hellman-group-exchange-sha256; do
    if ssh_run "$SSH96" 2231 127.0.0.1 $RSA $L -o KexAlgorithms="$kex" && kex_is "$kex"; then pass "legacy.kex_$kex"; else fail "legacy.kex_$kex"; fi
  done
  for c in 3des-cbc aes128-cbc aes192-cbc aes256-cbc; do
    expect_ok "legacy.cipher_$c" "$SSH96" 2231 127.0.0.1 $RSA $L -o KexAlgorithms=+diffie-hellman-group14-sha1 -o Ciphers="$c"
  done
  for m in hmac-sha1 hmac-sha1-96 hmac-md5 hmac-md5-96; do
    expect_ok "legacy.mac_$m" "$SSH96" 2231 127.0.0.1 $RSA $L -o KexAlgorithms=+diffie-hellman-group14-sha1 -o MACs="$m"
  done
  expect_ok "legacy.hostkey_ssh-dss" "$SSH96" 2231 127.0.0.1 $RSA $L -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=ssh-dss
  expect_ok "legacy.userkey_ssh-rsa_sha1" "$SSH96" 2231 127.0.0.1 $RSA $L -o KexAlgorithms=+diffie-hellman-group14-sha1 -o PubkeyAcceptedAlgorithms=ssh-rsa
else skip legacy "not running"; fi
if up legacy3des; then
  expect_ok "legacy3des.only_choice" "$SSH96" 2238 127.0.0.1 $RSA -o Ciphers=3des-cbc -o MACs=hmac-sha1 \
    -o KexAlgorithms=diffie-hellman-group14-sha1 -o HostKeyAlgorithms=ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
  expect_fail "legacy3des.refuses_aes-ctr" "$SSH96" 2238 127.0.0.1 $RSA -o Ciphers=aes128-ctr -o MACs=hmac-sha1 \
    -o KexAlgorithms=diffie-hellman-group14-sha1 -o HostKeyAlgorithms=ssh-rsa
else skip legacy3des "not running"; fi

# ---- jumps
if up bastion1 && up target; then
  CFG="$T/cfgj"
  expect_ok "jump2.bastion1_target" "$SSH96" 2234 127.0.0.2 $ED -J "$U@127.0.0.1:2232"
  if up bastion2; then
    expect_ok "jump3.bastion1_bastion2_target" "$SSH96" 2234 127.0.0.2 $ED -J "$U@127.0.0.1:2232,$U@127.0.0.2:2233"
  fi
  expect_fail "target.no_listener_on_127.0.0.1" "$SSH96" 2234 127.0.0.1 $ED
  CFG="$T/cfg"
else skip jump "bastion1/target not running"; fi

# ---- cert
if up cert; then
  CK="-o UserKnownHostsFile=$T/kh"
  expect_ok "cert.user_cert_ed25519+host_cert" "$SSH96" 2235 127.0.0.1 $ED -o CertificateFile="$K/client_ed25519-cert.pub" -o HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com
  expect_ok "cert.user_cert_rsa" "$SSH96" 2235 127.0.0.1 $RSA -o CertificateFile="$K/client_rsa-cert.pub"
  expect_ok "cert.user_cert_ecdsa" "$SSH96" 2235 127.0.0.1 -i "$K/client_ecdsa" -o CertificateFile="$K/client_ecdsa-cert.pub"
  cp "$K/client_ed25519" "$T/nocert"; chmod 600 "$T/nocert"
  expect_fail "cert.plain_key_refused" "$SSH96" 2235 127.0.0.1 -i "$T/nocert"
  for b in expired wrongprinc revoked; do
    expect_fail "cert.${b}_refused" "$SSH96" 2235 127.0.0.1 -i "$K/client_$b" -o CertificateFile="$K/client_$b-cert.pub"
  done
  grep -v "^\[127.0.0.1\]:2235" "$T/kh" > "$T/kh_ca"
  if "$SSH96" -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$T/kh_ca" \
       -o IdentitiesOnly=yes -i "$K/client_ed25519" -o HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com \
       -p 2235 "$U@127.0.0.1" true > "$T/out" 2>&1; then pass "cert.host_ca_only_known_hosts"
  else fail "cert.host_ca_only_known_hosts"; fi
else skip cert "not running"; fi

# ---- rotate (UpdateHostKeys / hostkeys-00@openssh.com); leaves the instance in mode a
if up rotate; then
  A="$(cut -d' ' -f1,2 "$FIX/rotate/host_a.pub")"; B="$(cut -d' ' -f1,2 "$FIX/rotate/host_b.pub")"
  echo "[127.0.0.1]:2236 $A" > "$T/kh_rot"
  sh "$HERE/fixture.sh" rotate ab > /dev/null
  "$SSH10" -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$T/kh_rot" \
    -o UpdateHostKeys=yes -o IdentitiesOnly=yes -i "$K/client_ed25519" -p 2236 "$U@127.0.0.1" true > "$T/out" 2>&1
  if grep -q "${B#* }" "$T/kh_rot"; then pass "rotate.key_b_learned_via_hostkeys-00"; else fail "rotate.key_b_learned_via_hostkeys-00"; fi
  sh "$HERE/fixture.sh" rotate b > /dev/null
  if "$SSH10" -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$T/kh_rot" \
       -o UpdateHostKeys=yes -o IdentitiesOnly=yes -i "$K/client_ed25519" -p 2236 "$U@127.0.0.1" true > "$T/out" 2>&1
  then pass "rotate.key_b_only_accepted"; else fail "rotate.key_b_only_accepted"; fi
  if grep -q "${A#* }" "$T/kh_rot"; then fail "rotate.key_a_removed_after_rotation"; else pass "rotate.key_a_removed_after_rotation"; fi
  sh "$HERE/fixture.sh" rotate a > /dev/null
else skip rotate "not running"; fi

# ---- otp
if up otp; then
  skip otp.login "interactive TOTP login is exercised by the ShellDrive tests; code: fixture.sh otp-code"
else skip otp "not running (needs the one-time sudo step: fixture.sh otp-pam)"; fi

# ---- proxies (raw handshakes + a full ssh login through each)
P="python3 -I $HERE/proxies/probe.py"
PC="sdproxy:shelldrive-proxy-pass"
check_status() { got="$($P --status "$2" "$3" "$4" "$5" ${6:-} 2>&1)"; if [ "$got" = "$7" ]; then pass "$1"; else fail "$1 (got $got, want $7)"; fi; }
if running "$FIX/proxy-http/pid"; then
  check_status "http.connect" http 127.0.0.1:2280 127.0.0.1 2230 "" 200
  check_status "http.dest_not_allowed" http 127.0.0.1:2280 192.0.2.1 22 "" 403
  expect_ok "http.ssh_through_proxy" "$SSH10" 2230 127.0.0.1 $ED -o ProxyCommand="$P http 127.0.0.1:2280 %h %p"
fi
if running "$FIX/proxy-http-auth/pid"; then
  check_status "http-auth.no_credentials_407" http 127.0.0.1:2281 127.0.0.1 2230 "" 407
  check_status "http-auth.bad_credentials_407" http 127.0.0.1:2281 127.0.0.1 2230 "sdproxy:wrong" 407
  check_status "http-auth.basic_ok" http 127.0.0.1:2281 127.0.0.1 2230 "$PC" 200
fi
if running "$FIX/proxy-socks5/pid"; then
  check_status "socks5.connect_ipv4" socks5 127.0.0.1:2290 127.0.0.1 2230 "" 00
  check_status "socks5.connect_domain" socks5 127.0.0.1:2290 localhost 2230 "" 00
  check_status "socks5.dest_not_allowed" socks5 127.0.0.1:2290 192.0.2.1 22 "" 02
  check_status "socks5.refused" socks5 127.0.0.1:2290 127.0.0.1 2299 "" 05
  expect_ok "socks5.ssh_through_proxy" "$SSH10" 2230 127.0.0.1 $ED -o ProxyCommand="$P socks5 127.0.0.1:2290 %h %p"
fi
if running "$FIX/proxy-socks5-auth/pid"; then
  check_status "socks5-auth.no_auth_offered" socks5 127.0.0.1:2291 127.0.0.1 2230 "" no-method
  check_status "socks5-auth.bad_credentials" socks5 127.0.0.1:2291 127.0.0.1 2230 "sdproxy:wrong" auth-failed
  check_status "socks5-auth.rfc1929_ok" socks5 127.0.0.1:2291 127.0.0.1 2230 "$PC" 00
  # the M2 demo path without the OTP: SOCKS5 (auth) -> bastion1 -> target (10.x, ML-KEM)
  if up bastion1 && up target; then
    if ssh_run "$SSH10" 2234 127.0.0.2 $ED -o ProxyJump=none \
         -o ProxyCommand="$SSH10 -F $T/cfgj -o ProxyCommand='$P socks5 127.0.0.1:2291 %%h %%p $PC' -p 2232 -W %h:%p $U@127.0.0.1" &&
       kex_is mlkem768x25519-sha256; then pass "demo.socks5_bastion1_target_mlkem"; else fail "demo.socks5_bastion1_target_mlkem"; fi
  fi
fi

# ---- PPK files: checked with puttygen when it is installed
if command -v puttygen >/dev/null 2>&1; then
  for f in client_ed25519.ppk client_rsa.ppk client_ecdsa.ppk client_ed25519_v2.ppk; do
    a="$(puttygen "$K/$f" -O public-openssh 2>/dev/null | cut -d' ' -f1,2)"
    b="$(cut -d' ' -f1,2 "$K/${f%%.ppk}.pub" 2>/dev/null || cut -d' ' -f1,2 "$K/client_ed25519.pub")"
    [ "$f" = client_ed25519_v2.ppk ] && b="$(cut -d' ' -f1,2 "$K/client_ed25519.pub")"
    if [ -n "$a" ] && [ "$a" = "$b" ]; then pass "ppk.$f"; else fail "ppk.$f"; fi
  done
else skip ppk "puttygen not installed (sudo apt install putty-tools)"; fi

echo "selftest: $FAILS failure(s)"
[ "$FAILS" -eq 0 ]
