#!/bin/sh
# Run the tests inside a machine

if [ ! -d '/shared' ]
then
    echo >&2 "Error: /shared directory not found"
    exit 1
fi

cd '/shared' || exit $?

# Find installed kernel headers revision
# * Debian package: linux-headers-amd64
# * Ubuntu package: linux-headers-generic
# * Fedora package: kernel-devel
KERNELVER="$(LANG=C dpkg --status linux-headers-amd64 linux-headers-generic 2>/dev/null |
    sed -n 's/^Depends: linux-headers-\(.*\)/\1/p' | head -n 1)"
if [ -z "$KERNELVER" ]
then
    KERNELVER="$(LANG=C rpm -qi kernel-devel 2>/dev/null |
        sed -n 's/^Source RPM *: kernel-\(.*\).src.rpm$/\1.x86_64/p' | tail -n 1)"
fi
export KERNELVER

# Do not use unicode in MinGW<4.8, when "wmain" is not automatically declared
case "$(x86_64-w64-mingw32-gcc --version 2>/dev/null | sed -n 's/^x86_64-w64-mingw32-gcc (GCC) //p')" in
    [123].*|4.[0-7].*)
        export HAVE_UNICODE=n
        ;;
esac

echo '******************************************'
echo '* Building with gcc                      *'
echo '******************************************'
make CC=gcc clean test || exit $?

# Do not build the kernel modules with modified compiler
KERNELVER=

if [ -x /usr/bin/clang ] || clang --version 2>/dev/null
then
    echo '******************************************'
    echo '* Building with clang                    *'
    echo '******************************************'
    make CC=clang clean test HAVE_OPENMP=n HAVE_GTK3=n HAVE_PYTHON_CFFI=n || exit $?
fi

if [ -x /usr/bin/musl-gcc ] || musl-gcc --version 2>/dev/null
then
    echo '******************************************'
    echo '* Building with musl-gcc                 *'
    echo '******************************************'
    make CC=musl-gcc clean test HAVE_LIBMNL=n HAVE_PULSE=n HAVE_SDL2=n HAVE_PYTHON_CFFI=n || exit $?
fi

make list-nobuild
