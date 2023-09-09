#!/bin/sh
# Some gpg keys appear to often disappear from keyserver.ubuntu.com.
# Ensure they are still present by sending our copy of them.

set -eu
cd "$(dirname -- "$0")"


GNUPGHOME="$(mktemp -d "${TMPDIR:-/tmp}/send-gpg-keys-XXXXXX")"
export GNUPGHOME
trap 'rm -r "$GNUPGHOME"' EXIT HUP INT QUIT TERM

HOME="$GNUPGHOME"
export HOME

# 0x2F3898CEDEE958CF is Facebook
# 0x872F702C4D6E25A8 is bubulle@debian.org
for KEYFILE in \
    all_keys/Facebook_2F3898CEDEE958CF.asc \
    all_keys/bubulle_debian.org_872F702C4D6E25A8.asc
do
    KEYID="$(gpg --list-packets "$KEYFILE" | sed -n 's/^\s*keyid: \([0-9A-F]\+\)$/\1/p' | head -n1)"
    gpg --import "$KEYFILE"
    gpg --keyserver hkps://keyserver.ubuntu.com --send-keys "0x$KEYID"
done
