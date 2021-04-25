#!/bin/sh
# Run the tests inside a machine

if [ ! -d '/shared' ]
then
    echo >&2 "Error: /shared directory not found"
    exit 1
fi

cd '/shared' || exit $?

# Find installed kernel headers revision
case "$(sed -n 's/^ID=//p' /etc/os-release /usr/lib/os-release 2>/dev/null | head -n 1)" in
    alpine)
        KERNELVER="$(apk info --contents linux-grsec-dev linux-hardened-dev linux-lts-dev linux-vanilla-dev 2>/dev/null |
            sed -n 's:^lib/modules/\([^/][^/]*\)/.*:\1:p' | head -n 1)"
        ;;
    arch)
        KERNELVER="$(pacman -Qql linux-headers |
            sed -n 's:^/usr/lib/modules/\([^/]\+\)/.*:\1:p' | head -n 1)"
        ;;
    debian)
        KERNELVER="$(LANG=C dpkg --status linux-headers-amd64 2>/dev/null |
            sed -n 's/^Depends: linux-headers-\([^ ]*\)\( .*\)\?/\1/p' | head -n 1)"
        ;;
    fedora)
        KERNELVER="$(LANG=C rpm -qi kernel-devel 2>/dev/null |
            sed -n 's/^Source RPM *: kernel-\(.*\).src.rpm$/\1.x86_64/p' | tail -n 1)"
        ;;
    gentoo)
        KERNELVER="$(LANG=C eselect --brief kernel show 2>/dev/null |
            sed -n 's:^\s*/usr/src/linux-::p' | head -n 1)-$(uname -m)"
        ;;
    ubuntu)
        KERNELVER="$(LANG=C dpkg --status linux-headers-generic 2>/dev/null |
            sed -n 's/^Depends: linux-headers-\(.*\)/\1/p' | head -n 1)"
        ;;
esac
export KERNELVER

# Do not use unicode in MinGW<4.8, when "wmain" is not automatically declared
case "$(x86_64-w64-mingw32-gcc --version 2>/dev/null | sed -n 's/^x86_64-w64-mingw32-gcc (GCC) //p')" in
    [123].*|4.[0-7].*)
        export HAVE_UNICODE=n
        ;;
esac

# On Ubuntu 12.04 and 14.04, wine needs CAP_SYS_RAWIO=0x20000, so the Docker
# container needs to be executed with "docker run --cap-add SYS_RAWIO" in order
# to run Wine.
# Otherwise, wine shows:
#   /usr/bin/wine: error while loading shared libraries: libwine.so.1:
#   cannot create shared object descriptor: Operation not permitted
# and strace:
#   mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 EPERM (Operation not permitted)
if grep '^VERSION="1[24]\.04.* LTS' /etc/os-release > /dev/null
then
    if grep '^CapEff:\s*0..........[014589cd]....$' /proc/self/status > /dev/null
    then
        echo >&2 "CAP_SYS_RAWIO is not enabled but is needed by wine on Ubuntu<16.04, disabling wine"
        WINE=false
        export WINE
    fi
fi

# Gentoo and Sabayon install clang in /usr/lib/llvm/$VERSION/bin/clang
# Add this directory to $PATH if clang does not exist in current $PATH.
if ! clang --version 2>/dev/null
then
    LLVM_DIR="$(ls -1 -d /usr/lib/llvm/*/bin 2> /dev/null | head -n1)"
    if [ -n "$LLVM_DIR" ]
    then
        PATH="$LLVM_DIR:$PATH"
    fi
fi

# Temporary file to test compilation
TMPOUT="$(mktemp -p "${TMPDIR:-/tmp}" run_shared_test_cc.out.XXXXXXXXXX)"
if [ "$?" -ne 0 ] || [ -z "$TMPOUT" ]
then
    echo >&2 'Fatal error: unable to create a temporary file!'
    exit 1
fi
trap 'rm -f "$TMPOUT"' EXIT HUP INT QUIT TERM

# Use --list-nobuild to only show make list-nobuild without building everything
if [ "${1:-}" != "--list-nobuild" ]
then
    echo '******************************************'
    echo '* Building with gcc                      *'
    echo '******************************************'
    make CC=gcc clean test || exit $?

    # Compile 32-bit version if supported, but without any library
    if echo 'int main(void){return 0;}' | gcc -m32 -Werror -x c -o"$TMPOUT" - 2>/dev/null
    then
        echo '******************************************'
        echo '* Building with gcc -m32                 *'
        echo '******************************************'
        # Use linux32 to build 32-bit Windows programs too (the detection uses uname -m)
        # Do not build kernel modules with an incompatible compiler
        # Do not build Rust projects, that have C dependencies
        linux32 make CC='gcc -m32' CARGO=false clean test KERNELVER= || exit $?
    fi

    if [ -x /usr/bin/clang ] || clang --version 2>/dev/null
    then
        echo '******************************************'
        echo '* Building with clang                    *'
        echo '******************************************'
        make CC=clang clean test KERNELVER= || exit $?
        if echo 'int main(void){return 0;}' | clang -m32 -Werror -x c -o"$TMPOUT" - 2>/dev/null
        then
            echo '******************************************'
            echo '* Building with clang -m32               *'
            echo '******************************************'
            linux32 make CC='clang -m32' CARGO=false clean test KERNELVER= || exit $?
        fi
    fi

    if [ -x /usr/bin/musl-gcc ] || musl-gcc --version 2>/dev/null
    then
        echo '******************************************'
        echo '* Building with musl-gcc                 *'
        echo '******************************************'
        make CC='musl-gcc -shared -fPIE -pie' CARGO=false clean test KERNELVER= || exit $?
    fi
fi

echo '******************************************'
echo '* Output of make list-nobuild            *'
echo '******************************************'

# List blacklist with default compiler
make list-nobuild || exit $?

# List blacklist with 32-bit compiler
if echo 'int main(void){return 0;}' | gcc -m32 -Werror -x c -o"$TMPOUT" - 2>/dev/null
then
    echo 'With gcc -m32:'
    make CC='gcc -m32' list-nobuild | sed 's/^/   /'
fi

# List used compilers
echo 'Compilers:'
for COMPILER in gcc clang
do
    for BITMODE in 64 32
    do
        if echo 'int main(void){return 0;}' | "$COMPILER" -m"$BITMODE" -Werror -x c -o"$TMPOUT" - 2>/dev/null
        then
            if "$TMPOUT"
            then
                echo "   $COMPILER -m$BITMODE: ok"
            else
                echo "   $COMPILER -m$BITMODE: only compiling"
            fi
        else
            echo "   $COMPILER -m$BITMODE: not working"
        fi
    done
done
COMPILER=musl-gcc
if echo 'int main(void){return 0;}' | "$COMPILER" -Werror -x c -o"$TMPOUT" - 2>/dev/null
then
    if "$TMPOUT"
    then
        echo "   $COMPILER: ok"
    else
        echo "   $COMPILER: only compiling"
    fi
else
    echo "   $COMPILER: not working"
fi
COMPILER=x86_64-w64-mingw32-gcc
if echo 'int main(void){return 0;}' | "$COMPILER" -Werror -x c -o"$TMPOUT" - 2>/dev/null
then
    if WINEARCH=win64 "${WINE:-wine}" "$TMPOUT" >/dev/null 2>&1
    then
        echo "   $COMPILER: ok"
    else
        echo "   $COMPILER: only compiling"
    fi
else
    echo "   $COMPILER: not working"
fi
COMPILER=i686-w64-mingw32-gcc
if echo 'int main(void){return 0;}' | "$COMPILER" -Werror -x c -o"$TMPOUT" - 2>/dev/null
then
    if "${WINE:-wine}" "$TMPOUT" >/dev/null 2>&1
    then
        echo "   $COMPILER: ok"
    else
        echo "   $COMPILER: only compiling"
    fi
else
    echo "   $COMPILER: not working"
fi

echo 'Versions:'
./machines/show_versions.sh | sed 's/^/   /'

echo 'Done running tests.'
