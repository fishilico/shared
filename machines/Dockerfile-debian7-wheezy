FROM debian:wheezy-slim
LABEL Description="Debian 7 Wheezy with build dependencies for shared"

# Override the language to force UTF-8 output
ENV LANG C.UTF-8

# Do not install coq because it is too old (8.3pl4) for some features
# Do not install wine because it is too old (1.4.1) to work in containers
# Debian<9 does not provide python-z3
RUN \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get -qq update && \
    mkdir -p /usr/share/man/man1 && \
    apt-get install --no-install-recommends --no-install-suggests -qqy \
        binutils-mingw-w64 \
        clang \
        gcc-mingw-w64 \
        gcc-multilib \
        gdb \
        libc-dev \
        libc6-dev-i386 \
        libgmp-dev \
        libgtk-3-dev \
        libmnl-dev \
        libpulse-dev \
        linux-headers-amd64 \
        make \
        openjdk-7-jdk \
        openssh-client \
        openssl \
        pkg-config \
        python3 \
        python3-crypto \
        python3-numpy \
        python-argparse \
        python-crypto \
        python-numpy && \
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
#       linux: sdl_v4l_video seccomp
#       python: cffi_example.py cffi_numpy.py udp_multihome.py z3_example.py
#       python/crypto:
#       python/dnssec:
#       verification: ackermann.vo
#    With gcc -m32:
#       Global blacklist: latex%
#       In sub-directories:
#          c: gmp_functions gtk_alpha_window
#          java/keystore:
#          linux: enum_link_addrs pulseaudio_echo sdl_v4l_video seccomp
#          python: cffi_example.py cffi_numpy.py udp_multihome.py z3_example.py
#          python/crypto:
#          python/dnssec:
#          verification: ackermann.vo
#    Compilers:
#       gcc -m64: ok
#       gcc -m32: ok
#       clang -m64: ok
#       clang -m32: not working
#       musl-gcc: not working
#       x86_64-w64-mingw32-gcc: only compiling
#       i686-w64-mingw32-gcc: only compiling
