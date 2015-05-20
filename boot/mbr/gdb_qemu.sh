#!/bin/sh
# Boot a disk image with QEMU, attach it with gdb, and debug it
# In gdb, use "tb *($eip+2)" and "c" to step over BIOS interrupts, when doing
# step-by-step execution.

# Create a file where to store qemu PID
QEMU_PIDFILE=$(mktemp --tmpdir qemu_XXXXXXXXXX.pid)
[ -n "$QEMU_PIDFILE" ] || exit 1

# Launch gdb, which attach to qemu using -S to prevent the CPU from starting
gdb -q \
    -ex "target remote | exec qemu-system-i386 -gdb stdio -S -pidfile '$QEMU_PIDFILE' $*" \
    -ex 'set architecture i8086' \
    -ex 'break *0x7c00' \
    -ex 'continue'

# Kill qemu
QEMU_PID="$(cat "$QEMU_PIDFILE" 2>/dev/null)"
if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null
then
    echo "Terminating QEMU process $QEMU_PID"
    kill "$QEMU_PID"
fi
rm -f "$QEMU_PIDFILE"
