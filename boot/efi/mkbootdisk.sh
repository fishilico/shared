#!/bin/sh
# Create a bootable disk image from a .efi file
# Usage:
#    mkbootdisk.sh image.efi              Create image.disk with an EFI partition with image.efi
#    mkbootdisk.sh image.efi output.disk  Create output.disk with an EFI partition with image.efi
#    mkbootdisk.sh -t image.efi           Create image.disk in /tmp
#    mkbootdisk.sh -r image.efi           Create image.disk and run it
#
# Here are some command lines to run the image with QEMU in the old way (before 2016):
# * qemu-system-x86_64 -bios /usr/share/ovmf/ovmf_x64.bin -hda image.disk -serial stdio -display none
# * qemu-system-i386 -bios /usr/share/ovmf/ovmf_ia32.bin -hda image.disk -serial stdio -display none
#
# To run the image in QEMU in the new way, with a split OVMF file:
# * qemu-system-x86_64 \
#     -drive if=pflash,format=raw,readonly=on,file=/usr/share/ovmf/x64/OVMF_CODE.fd \
#     -drive if=pflash,format=raw,file=copy_of_OVMF_VARS.fd \
#     -drive if=virtio,format=raw,file=image.disk -serial stdio -display none
#
# Such a logic has also been implemented in Debian to test edk2:
# https://salsa.debian.org/qemu-team/edk2/-/blob/31c48f28db6083d7f8238b56fd31aedbc1fcde6b/debian/python/UEFI/Qemu.py

# Create a disk able to store several 512-byte sectors
FAT_NUMSECT=200

# Parse command line
ARCH=
USE_TMP=false
RUN_IMAGE=false

while getopts ":a:hrt" OPT
do
    case "$OPT" in
        a)
            ARCH="$OPTARG"
            ;;
        h)
            echo "Usage: $0 [OPTIONS] EFI_FILE [DISK_FILE]"
            echo "Create a bootable disk image from a .efi file"
            echo "options:"
            echo "    -a ARCH   Specify the architecture"
            echo "    -r        Create the image disk and run it with QEmu"
            echo "    -t        Create the image disk in /tmp"
            exit 0
            ;;
        r)
            RUN_IMAGE=true
            ;;
        t)
            USE_TMP=true
            ;;
        \?)
            echo >&2 "$0: invalid option '$OPTARG'"
            echo >&2 "Try '$0 --help' for more information."
            exit 1
            ;;
    esac
done

shift $((OPTIND-1))
if [ $# -lt 1 ]
then
    echo >&2 "Not enough parameters"
    exit 1
fi

EFI_IMAGE="$1"

# Retrieve the arch
if [ -z "$ARCH" ]
then
    OBJ_ARCH=$(LANG=C objdump -a "$EFI_IMAGE" | sed -n 's/^.*file format \([0-9a-zA-Z_.-]\+\)/\1/p')
    case "$OBJ_ARCH" in
        pei-x86-64)
            ARCH=x86_64
            ;;
        pei-i386)
            ARCH=ia32
            ;;
        "")
            echo >&2 "Error while finding the type of $EFI_IMAGE"
            exit 1
            ;;
        *)
            echo >&2 "Unknown file type $OBJ_ARCH for $EFI_IMAGE"
            exit 1
            ;;
    esac
fi

# OVMF firmware:
# - Arch Linux https://archlinux.org/packages/extra/any/edk2-ovmf/
#       /usr/share/edk2-ovmf/x64/OVMF_CODE.fd
#       /usr/share/edk2-ovmf/x64/OVMF_VARS.fd
#       /usr/share/edk2-ovmf/ia32/OVMF_CODE.fd
#       /usr/share/edk2-ovmf/ia32/OVMF_VARS.fd
#       /usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd
#       /usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd
#       /usr/share/edk2-ovmf/ia32/OVMF_CODE.4m.fd
#       /usr/share/edk2-ovmf/ia32/OVMF_VARS.4m.fd
# - Debian https://packages.debian.org/fr/sid/all/ovmf/filelist
#       /usr/share/OVMF/OVMF_CODE.fd
#       /usr/share/OVMF/OVMF_VARS.fd
# - Debian https://packages.debian.org/fr/sid/all/ovmf-ia32/filelist
#       /usr/share/OVMF/OVMF32_CODE_4M.secboot.fd
#       /usr/share/OVMF/OVMF32_VARS_4M.fd
# - Fedora https://fedora.pkgs.org/35/fedora-updates-x86_64/edk2-ovmf-20211126gitbb1bba3d7767-1.fc35.noarch.rpm.html
#       /usr/share/edk2/ovmf/OVMF_CODE.fd
#       /usr/share/edk2/ovmf/OVMF_VARS.fd

OVMF_CODE=
case "$ARCH" in
    x86_64)
        EFI_FILE_IN_PART="/EFI/BOOT/BOOTX64.efi"
        QEMU_COMMAND="qemu-system-x86_64"
        for FILE in /usr/share/edk2-ovmf/x64/OVMF_CODE.fd /usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_CODE.fd
        do
            if [ -e "$FILE" ]
            then
                OVMF_CODE="$FILE"
                break
            fi
        done
        ;;
    ia32)
        EFI_FILE_IN_PART="/EFI/BOOT/BOOTIA32.efi"
        QEMU_COMMAND="qemu-system-i386"
        for FILE in /usr/share/edk2-ovmf/ia32/OVMF_CODE.fd /usr/share/edk2-ovmf/ia32/OVMF_CODE.4m.fd /usr/share/OVMF/OVMF32_CODE_4M.secboot.fd
        do
            if [ -e "$FILE" ]
            then
                OVMF_CODE="$FILE"
                break
            fi
        done
        ;;
    *)
        echo >&2 "Unknown architecture $ARCH"
        exit 1
        ;;
esac
if [ -z "$OVMF_CODE" ]
then
    echo >&2 "Unable to find OVMF firmware in /usr/share"
    exit 1
fi

OVMF_VARS="$(printf "%s" "$OVMF_CODE" | sed 's/_CODE/_VARS/' | sed 's/\.secboot\.fd$/.fd/')"
if [ -z "$OVMF_VARS" ]
then
    echo >&2 "Unable to find OVMF matching variables template $OVMF_VARS for $OVMF_CODE"
    exit 1
fi

# Compute the output disk file name
if [ $# -ge 2 ]
then
    DISK_PATH="$2"
elif $USE_TMP
then
    BASENAME="$(basename "$EFI_IMAGE")"
    DISK_PATH="/tmp/${BASENAME%.efi}.disk"
else
    DISK_PATH="${EFI_IMAGE%.efi}.disk"
fi

# Create the disk image
rm -f "$DISK_PATH"
if ! dd status=none if=/dev/zero of="$DISK_PATH" bs=512 seek=$((2096+$FAT_NUMSECT)) count=0
then
    echo >&2 "Unable to create empty disk image $DISK_PATH"
    exit 1
fi
while IFS= read -r COMMAND
do
    if ! parted --script "$DISK_PATH" "$COMMAND"
    then
        echo >&2 "Error while running parted '$COMMAND'"
        exit 1
    fi
done << EOF
mktable gpt
mkpart primary fat32 2048s $((2048+$FAT_NUMSECT))s
set 1 boot on
name 1 UEFI
EOF

# Create a FAT partition
PART_FILE="$(mktemp)"
trap 'rm -f "$PART_FILE"' EXIT HUP INT QUIT TERM
if ! dd status=none conv=sparse if="$DISK_PATH" of="$PART_FILE" bs=512 skip=2048 count="$FAT_NUMSECT"
then
    echo >&2 "Unable to copy the partition from the disk"
    exit 1
fi
mkfs.vfat "$PART_FILE" > /dev/null || exit $?
export MTOOLS_SKIP_CHECK=1
mmd -i "$PART_FILE" ::/EFI || exit $?
mmd -i "$PART_FILE" ::/EFI/BOOT || exit $?
mcopy -i "$PART_FILE" "$EFI_IMAGE" "::$EFI_FILE_IN_PART" || exit $?

# Put the FAT partition into the disk image
if ! dd status=none conv=sparse,nocreat,notrunc if="$PART_FILE" of="$DISK_PATH" bs=512 seek=2048 count="$FAT_NUMSECT"
then
    echo >&2 "Unable to copy the partition back to the disk"
    exit 1
fi
rm "$PART_FILE"

if $RUN_IMAGE
then
    echo "Booting $DISK_PATH as an $ARCH UEFI disk"
    OVMF_VARS_TEMP="$(mktemp)"
    trap 'rm -f "$OVMF_VARS_TEMP"' EXIT HUP INT QUIT TERM
    cat < "$OVMF_VARS" > "$OVMF_VARS_TEMP"
    "$QEMU_COMMAND" \
        -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
        -drive "if=pflash,format=raw,file=$OVMF_VARS_TEMP" \
        -drive "format=raw,file=$DISK_PATH" \
        -serial stdio -no-reboot -display none
fi
