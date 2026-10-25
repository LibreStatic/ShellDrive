#!/bin/sh
# Regenerates the hk_* host key / certificate fixtures of the transport unit tests (test_known_hosts_m2.c)
# with OpenSSH's ssh-keygen (WSL). Public material only; the private keys are thrown away.
set -eu
D="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
cd "$T"
ssh-keygen -q -t ed25519 -N '' -C hk-ca -f ca
ssh-keygen -q -t ed25519 -N '' -C hk-ca2 -f ca2
ssh-keygen -q -t rsa -b 2048 -N '' -C hk-rsaca -f rsaca
ssh-keygen -q -t ed25519 -N '' -C hk-host -f hostkey
sign() { # name signer args...
  n="$1"; s="$2"; shift 2
  cp hostkey.pub "$n.pub"
  ssh-keygen -q -s "$s" "$@" "$n.pub"
  mv "$n-cert.pub" "hk_$n-cert.pub"
}
sign host ca -I ok -h -n host.example,127.0.0.1 -V always:forever
sign host_expired ca -I exp -h -n host.example -V 20200101:20200102
sign host_user ca -I usr -n host.example -V always:forever
sign host_noprinc ca -I noprinc -h -V always:forever
sign host_ca2 ca2 -I ca2 -h -n host.example -V always:forever
sign host_rsaca rsaca -I rsa512 -h -n host.example -V always:forever
sign host_rsasha1 rsaca -t ssh-rsa -I rsasha1 -h -n host.example -V always:forever
cp ca.pub hk_ca.pub; cp ca2.pub hk_ca2.pub; cp rsaca.pub hk_rsaca.pub; cp hostkey.pub hk_host.pub
{ echo "host.example $(cut -d' ' -f1,2 hostkey.pub)"; echo "[host.example]:2222 $(cut -d' ' -f1,2 hostkey.pub)"; } > hk_hashed_known_hosts
ssh-keygen -q -H -f hk_hashed_known_hosts >/dev/null 2>&1
rm -f hk_hashed_known_hosts.old
cp hk_* "$D/"
cd /; rm -rf "$T"
