#!/bin/sh
# Builds OpenSSH portable 10.x from the official release tarball into a user prefix inside WSL, for the M2
# interop fixtures (decisions.md D21: test infrastructure only; nothing of it ships). No sudo: needs gcc,
# make, zlib1g-dev and libssl-dev (Ubuntu 24.04 has them; see README.md for the no-OpenSSL fallback).
#
#   sh tests/fixtures/openssh10/build.sh            # idempotent: does nothing when the prefix is complete
#   SD_OSSH_FORCE=1 sh .../build.sh                 # rebuild
#   SD_OSSH_WITHOUT_OPENSSL=1 sh .../build.sh       # --without-openssl (internal crypto only)
#
# Verification (both must pass, otherwise nothing is extracted):
#   1. GPG signature (.asc) against the release key from the same CDN, imported into a private GNUPGHOME
#      (the user's keyring is not touched), and the signing key's fingerprint must equal RELEASE_FPR below;
#   2. SHA-256 of the tarball must equal SHA256_B64 below (base64, as published in the release notes at
#      https://www.openssh.com/txt/release-<version>).
# To move to a newer release, update VERSION, SHA256_B64 (from the release notes) and re-run with SD_OSSH_FORCE=1.
set -eu

VERSION="${SD_OSSH_VERSION:-10.6p1}"
SHA256_B64="${SD_OSSH_SHA256:-qdyVZd/+hkD2TYY80poyvEo9vewFZqf8RMXW7nZ9Xzk=}"
RELEASE_FPR="7168B983815A5EEF59A4ADFD2A3F414E736060BA"   # Damien Miller <djm@mindrot.org>
CDN="https://cdn.openbsd.org/pub/OpenBSD/OpenSSH"

FIX="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-fixtures"
PREFIX="$FIX/openssh-$VERSION"
DL="$FIX/build/dl"
SRC="$FIX/build/src"
LOGS="$FIX/build"

if [ -z "${SD_OSSH_FORCE:-}" ] && [ -x "$PREFIX/sbin/sshd" ] && [ -x "$PREFIX/libexec/sshd-session" ] &&
   "$PREFIX/sbin/sshd" -V 2>&1 | grep -q "OpenSSH_$VERSION"; then
  echo "OpenSSH $VERSION already built: $PREFIX"
  ln -sfn "$PREFIX" "$FIX/openssh10"
  exit 0
fi

for t in cc make curl gpg openssl tar; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 1; }
done

OPENSSL_FLAG=""
if [ -n "${SD_OSSH_WITHOUT_OPENSSL:-}" ]; then
  OPENSSL_FLAG="--without-openssl"
elif ! dpkg -s libssl-dev >/dev/null 2>&1 || ! dpkg -s zlib1g-dev >/dev/null 2>&1; then
  echo "libssl-dev or zlib1g-dev missing: building --without-openssl (see README.md); for the full build:" >&2
  echo "  sudo apt install libssl-dev zlib1g-dev" >&2
  OPENSSL_FLAG="--without-openssl"
fi

mkdir -p "$DL" "$SRC"
T="openssh-$VERSION.tar.gz"
cd "$DL"
[ -f "$T" ] || curl -fsSO "$CDN/portable/$T"
curl -fsSO "$CDN/portable/$T.asc"
curl -fsSO "$CDN/RELEASE_KEY.asc"

GNUPGHOME="$FIX/build/gnupg"; export GNUPGHOME
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
gpg -q --batch --import RELEASE_KEY.asc 2>/dev/null || true
STATUS="$(gpg --batch --status-fd 1 --verify "$T.asc" "$T" 2>/dev/null || true)"
echo "$STATUS" | grep -q "^\[GNUPG:\] GOODSIG " || { echo "GPG signature check FAILED for $T" >&2; exit 1; }
echo "$STATUS" | grep -q "^\[GNUPG:\] VALIDSIG $RELEASE_FPR " ||
  { echo "signature is not from the expected release key $RELEASE_FPR" >&2; exit 1; }
GOT="$(openssl dgst -sha256 -binary "$T" | base64)"
[ "$GOT" = "$SHA256_B64" ] || { echo "SHA-256 mismatch for $T: got $GOT, want $SHA256_B64" >&2; exit 1; }
echo "verified $T: GPG signature by $RELEASE_FPR and SHA-256 $GOT"

cd "$SRC"
rm -rf "openssh-$VERSION"
tar xzf "$DL/$T"
cd "openssh-$VERSION"
# PAM, Kerberos and SELinux off: the fixture sshds run unprivileged. The privsep path is inside the prefix.
./configure --prefix="$PREFIX" --sysconfdir="$PREFIX/etc" --with-privsep-path="$PREFIX/var/empty" \
  --with-pid-dir="$PREFIX/run" --without-pam --without-selinux --without-kerberos5 $OPENSSL_FLAG \
  > "$LOGS/configure.log" 2>&1 || { echo "configure failed, see $LOGS/configure.log" >&2; exit 1; }
make -j"$(nproc 2>/dev/null || echo 4)" > "$LOGS/make.log" 2>&1 || { echo "make failed, see $LOGS/make.log" >&2; exit 1; }
make install-nokeys > "$LOGS/install.log" 2>&1 || { echo "install failed, see $LOGS/install.log" >&2; exit 1; }
ln -sfn "$PREFIX" "$FIX/openssh10"
"$PREFIX/sbin/sshd" -V 2>&1 | head -n 1
echo "installed: $PREFIX (symlink $FIX/openssh10)"
