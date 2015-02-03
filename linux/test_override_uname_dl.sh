#!/bin/sh
# Test overriding uname() call with a shared object

# Path to things which are used
OVERRIDE_UNAME_SO="${OVERRIDE_UNAME_SO:-$(dirname "$0")/override_uname_dl.so}"
UNAME="${UNAME:-uname}"
UNAME_PATH="$(which $UNAME)"
if [ -z "$UNAME_PATH" ]
then
    echo >&2 "Error: unable to find uname ($UNAME)"
    exit 1
fi

# Test directly to see whether the override library and uname are compatible.
# This can fail when the libc (eg. library built with musl and uname with glibc).
if ! LD_PRELOAD="$OVERRIDE_UNAME_SO" "$UNAME" > /dev/null
then
    echo "An error occured in the compatibility check. Skipping test."
    exit
fi

# If the ELF class differs, the above check actually succeded. Check ELF Magic.
# This happens when the architecture differs (eg. when the library has been
# built in 32-bit mode but uname is 64-bit)
OVER_MAGIC="$(readelf --file-header "$OVERRIDE_UNAME_SO" | grep '^ *Magic')"
UNAME_MAGIC="$(readelf --file-header "$UNAME_PATH" | grep '^ *Magic')"
if [ "$OVER_MAGIC" != "$UNAME_MAGIC" ]
then
    echo "Different ELF magic headers. Skipping test."
    exit
fi

# Set overrided variables to markers
FAKEUNAME_S="FakeLinux"
FAKEUNAME_N="fakehostname"
FAKEUNAME_R="3.0.42-fake-kernel-release"
FAKEUNAME_V="Fake kernel version"
FAKEUNAME_M="whatever_machine"
export FAKEUNAME_S FAKEUNAME_N FAKEUNAME_R FAKEUNAME_V FAKEUNAME_M

# Check expected results
CHECK_RESULT=0

check_res() {
    local EXPECTED RESULT

    EXPECTED="$1"
    shift
    RESULT="$(LD_PRELOAD="$OVERRIDE_UNAME_SO" "$@")"

    if [ "$EXPECTED" = "$RESULT" ]
    then
        echo "[ OK ] $*"
    else
        echo "[FAIL] $*: $EXPECTED != $RESULT"
        CHECK_RESULT=1
    fi
}

# Test basic "uname"
check_res "$FAKEUNAME_S" "$UNAME" -s
check_res "$FAKEUNAME_N" "$UNAME" -n
check_res "$FAKEUNAME_R" "$UNAME" -r
check_res "$FAKEUNAME_V" "$UNAME" -v
check_res "$FAKEUNAME_M" "$UNAME" -m

# Test with a exec
check_res "$FAKEUNAME_S" sh -c "'$UNAME' -s"
check_res "$FAKEUNAME_N" sh -c "'$UNAME' -n"
check_res "$FAKEUNAME_R" sh -c "'$UNAME' -r"
check_res "$FAKEUNAME_V" sh -c "'$UNAME' -v"
check_res "$FAKEUNAME_M" sh -c "'$UNAME' -m"

# Test with a fork+exec
check_res "$FAKEUNAME_S" sh -c "'$UNAME' -s && true"
check_res "$FAKEUNAME_N" sh -c "'$UNAME' -n && true"
check_res "$FAKEUNAME_R" sh -c "'$UNAME' -r && true"
check_res "$FAKEUNAME_V" sh -c "'$UNAME' -v && true"
check_res "$FAKEUNAME_M" sh -c "'$UNAME' -m && true"

exit $CHECK_RESULT
