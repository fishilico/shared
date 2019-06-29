#!/usr/bin/env bash
# Test using the OpenPGP applet with GnuPG on a Yubikey 4
set -x -e

# Ensure the script is executed in the current directory
cd "$(dirname -- "$0")" || exit $?

# Remove any temporary file
rm -f ./*.tmp

# Retrieve the serial number
gpg-connect-agent 'SCD SERIALNO openpgp' /bye | sed 's/\(D276000124010201\)[0-9A-F]\{16\}/\1.../' | tee serailno.tmp
if ! diff serailno.tmp <(printf 'S SERIALNO D276000124010201...\nOK\n') ; then
    echo >&2 "Unexpected serial number"
    exit 1
fi

# Retrieve the ID of the GPG key
LANG=C gpg --card-status --keyid-format 0xlong | tee gpg-card-status.tmp
if grep '^Encryption key\.*: \[none\]' < gpg-card-status.tmp > /dev/null ; then
    echo >&2 "No encryption key :("
    exit 1
fi
KEYID="$(sed -n 's;^General key info\.\.: pub  [^ /]\+/\(0x[0-9A-F]\+\) .*;\1;p' gpg-card-status.tmp)"
if [ -z "$KEYID" ] ; then
    echo >&2 "Unable to find the General key info in gpg --card-status"
    exit 1
fi
echo "Using GPG key $KEYID"

# Test GPG encryption/decryption of a random message
head -c 409600 /dev/urandom > message.tmp
gpg --armor --encrypt --recipient="$KEYID" --output enc-msg.tmp message.tmp
gpg --decrypt --output dec-enc-msg.tmp enc-msg.tmp
if ! diff message.tmp dec-enc-msg.tmp ; then
    echo "Decrypted encrypted message does not match initial!"
    exit 1
fi

# Test GPG signature of a random message
gpg --armor --sign --detach-sign --default-key="$KEYID" --output signed-msg.tmp message.tmp
gpg --verify signed-msg.tmp message.tmp

# Clean-up
rm -f ./*.tmp
