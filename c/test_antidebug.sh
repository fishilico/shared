#!/bin/sh
# Test triggering every feature of antidebug

GDB=gdb

if [ "$OS" = "Windows_NT" ]
then
    # Windows OS
    BIN_EXT="exe"
    if [ "$(uname -s 2> /dev/null)" = "Linux" ]
    then
        echo >&2 "Skipping Windows testing on Linux."
        exit
    fi
else
    # non-Windows OS
    BIN_EXT="bin"
fi
PROG="$(dirname -- "$0")/antidebug.$BIN_EXT"

# Use "set" to expand the command array in sh
set -- $GDB
if ! which "$1" > /dev/null 2>&1
then
    echo >&2 "gdb is not installed. Skipping test."
    exit
fi

# In some Docker environments, tracing is not permitted
if ! "$@" --quiet -ex r --return-child-result true < /dev/null
then
    echo >&2 "gdb is not allowed here. Skipping test."
    exit
fi

# Test that the program without any instrumentation works
if ! "$PROG"
then
    echo >&2 "The program does not work!"
    exit 1
fi

"$@" --quiet --return-child-result < /dev/null \
    -ex 'b sensitive_computation' \
    -ex 'r' \
    "$PROG"
EXITCODE=$?

# antidebug program exits with code 3 when it has detected all debugging features
if [ $EXITCODE != 3 ]
then
    echo "Unexpected returned value: $EXITCODE"
    exit 1
fi
