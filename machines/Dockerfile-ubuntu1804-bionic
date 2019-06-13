FROM ubuntu:18.04
LABEL Description="Ubuntu 18.04 LTS Bionic Beaver with build dependencies for shared"

# Override the language to force UTF-8 output
ENV LANG C.UTF-8

RUN \
    export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture i386 && \
    apt-get -qq update && \
    apt-get install --no-install-recommends --no-install-suggests -qqy \
        binutils-mingw-w64 \
        clang \
        coq \
        gcc-mingw-w64 \
        gcc-multilib \
        gdb \
        libc-dev \
        libc6-dev-i386 \
        libgmp-dev \
        libgtk-3-dev \
        libmnl-dev \
        libpulse-dev \
        libsdl2-dev \
        linux-headers-generic \
        make \
        musl-dev \
        musl-tools \
        openjdk-11-jdk \
        openssh-client \
        openssl \
        pkg-config \
        python3 \
        python3-cffi \
        python3-crypto \
        python3-dev \
        python3-gmpy2 \
        python3-numpy \
        python-argparse \
        python-cffi \
        python-crypto \
        python-dev \
        python-gmpy2 \
        python-numpy \
        python-z3 \
        wine-stable \
        wine32 \
        wine64 && \
    apt-get clean

WORKDIR /shared
RUN ln -s shared/machines/run_shared_test.sh /run_shared_test.sh
COPY . /shared/

CMD ["/run_shared_test.sh"]

# make list-nobuild:
#    Global blacklist: latex%
#    In sub-directories:
#       c:
#       java/keystore:
#       linux:
#       python:
#       python/crypto:
#       python/dnssec:
#       verification:
#    With gcc -m32:
#       Global blacklist: latex%
#       In sub-directories:
#          c: gmp_functions gtk_alpha_window
#          java/keystore:
#          linux: enum_link_addrs pulseaudio_echo sdl_v4l_video
#          python:
#          python/crypto:
#          python/dnssec:
#          verification:
#    Compilers:
#       gcc -m64: ok
#       gcc -m32: ok
#       clang -m64: ok
#       clang -m32: ok
#       musl-gcc: ok
#       x86_64-w64-mingw32-gcc: ok
#       i686-w64-mingw32-gcc: ok
