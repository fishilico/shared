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
        KERNELVER="$(apk info --contents linux-grsec-dev linux-hardened-dev |
            sed -n 's:^lib/modules/\([^/]\+\)/.*:\1:p' | head -n 1)"
        ;;
    arch)
        KERNELVER="$(pacman -Qql linux-headers |
            sed -n 's:^/usr/lib/modules/\([^/]\+\)/.*:\1:p' | head -n 1)"
        ;;
    debian)
        KERNELVER="$(LANG=C dpkg --status linux-headers-amd64 2>/dev/null |
            sed -n 's/^Depends: linux-headers-\(.*\)/\1/p' | head -n 1)"
        ;;
    fedora)
        KERNELVER="$(LANG=C rpm -qi kernel-devel 2>/dev/null |
            sed -n 's/^Source RPM *: kernel-\(.*\).src.rpm$/\1.x86_64/p' | tail -n 1)"
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

# Use --list-nobuild to only show make list-nobuild
if [ "${1:-}" = "--list-nobuild" ]
then
    make list-nobuild
    exit $?
fi

echo '******************************************'
echo '* Building with gcc                      *'
echo '******************************************'
make CC=gcc clean test || exit $?

if [ -x /usr/bin/clang ] || clang --version 2>/dev/null
then
    echo '******************************************'
    echo '* Building with clang                    *'
    echo '******************************************'
    make CC=clang clean test HAVE_OPENMP=n HAVE_PYTHON_CFFI=n KERNELVER= || exit $?
fi

if [ -x /usr/bin/musl-gcc ] || musl-gcc --version 2>/dev/null
then
    echo '******************************************'
    echo '* Building with musl-gcc                 *'
    echo '******************************************'
    make CC="musl-gcc -shared" clean test HAVE_PYTHON_CFFI=n KERNELVER= || exit $?
fi

make list-nobuild
