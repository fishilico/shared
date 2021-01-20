#!/bin/sh
# Test triggering every feature of antidebug

GDB=gdb

if [ -n "$RUN_TEST_PREFIX" ]
then
    echo >&2 "Skipping non-native test because RUN_TEST_PREFIX is defined."
    exit
fi

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
GDB_COMMANDS="${PROG}.gdbinit"

# Use "set" to expand the command array in sh
set -- $GDB
if ! which "$1" > /dev/null 2>&1
then
    echo >&2 "gdb is not installed. Skipping test."
    exit
fi

# In some Docker environments, tracing is not permitted
if ! "$@" --quiet -ex run -ex quit --return-child-result true < /dev/null
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

# Write commands in a file, in order to prevent space splitting issues on Windows with "-ex 'break ...'"
cat > "$GDB_COMMANDS" << EOF
break sensitive_computation
run
quit
EOF

"$@" --quiet --batch --command="$GDB_COMMANDS" --return-child-result < /dev/null \
    "$PROG"
EXITCODE=$?
rm -f "$GDB_COMMANDS"

# antidebug program exits with code 3 when it has detected all debugging features
if [ $EXITCODE != 3 ]
then
    echo "Unexpected returned value: $EXITCODE"
    exit 1
fi
