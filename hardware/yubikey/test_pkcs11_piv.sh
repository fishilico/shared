#!/usr/bin/env bash
# Test interacting with the PIV applet of a connected Yubikey using pkcs11-tool

# Ensure the script is executed in the current directory
cd "$(dirname -- "$0")" || exit $?

# Run a command, showing it and returning its exit code
run_cmd() {
    echo >&2 "+ $*"
    "$@"
}

# Enumerate certificates
CERT_LIST="$(run_cmd pkcs15-tool --list-certificates)"
if [ -z "$CERT_LIST" ] ; then
    echo >&2 "No PCKS#15 smart card found"
    exit 1
fi
echo "$CERT_LIST"
echo ''

# Show the supported mechanism
run_cmd pkcs11-tool -v --list-mechanisms || exit $?
echo ''

# Make sure the tty is sane, in order to prompt the PIN
stty sane

# Remove any temporary file
rm -f ./*.tmp

for CERT_ID in $(echo "$CERT_LIST" | sed -n 's/^\s*ID\s*:\s*\([0-9A-Fa-f].*\)$/\1/p') ; do
    # Check the ID of the certificate
    if ! (echo "$CERT_ID" | grep '^[0-9A-Fa-f]\+$' > /dev/null) ; then
        echo >&2 "Invalid certificate ID: $CERT_ID"
        exit 1
    fi

    # Read the PIV certificate using PKCS15 interface
    CERT_FILE="piv_certificate_$CERT_ID.crt"
    rm -f "./$CERT_FILE"
    run_cmd pkcs15-tool --read-certificate "$CERT_ID" --output "./$CERT_FILE" || exit $?

    # Show the certificate
    run_cmd openssl x509 -noout -text -in "./$CERT_FILE" || exit $?

    echo ''

    # Generate a random message that can be encrypted using RSA2048 in PKCS#1 v1.5 mode
    # python -c "print('A'*245, end='')" > message.tmp
    (head -c 245 /dev/urandom) > message.tmp

    # Sign the message using the private key
    run_cmd pkcs11-tool -v --sign --id "$CERT_ID" --mechanism SHA256-RSA-PKCS --input-file message.tmp --output-file signature-message.tmp || exit $?

    # Verify the PKCS#1-v1.5 signature using the certificate
    run_cmd openssl rsautl -verify -pkcs -certin -inkey "./$CERT_FILE" -in signature-message.tmp -out signature-ver-message.tmp || exit $?

    echo ''

    # Encrypt the message using the public key in the certificate
    run_cmd openssl rsautl -encrypt -pkcs -certin -inkey "./$CERT_FILE" -in message.tmp -out encrypted-message.tmp || exit $?

    # Decrypt the file using the private key on the Yubikey, prompting for a PIN
    run_cmd pkcs11-tool -v --decrypt --mechanism RSA-PKCS --input-file encrypted-message.tmp --output-file decrypted-message.tmp || exit $?
    if ! run_cmd diff message.tmp decrypted-message.tmp ; then
        echo >&2 "The decryption of the encrypted message differs with the original message!"
        exit 1
    fi

    # Clean-up
    rm ./*.tmp
done

echo 'All Good :)'
