FROM ubuntu:12.04
LABEL Description="Ubuntu 12.04 LTS Precise Pangolin with build dependencies for shared"

# Override the language to force UTF-8 output
ENV LANG C.UTF-8

# Do not install coq because it is too old (8.3pl4) for some features
# Do not install libmnl-dev because mnl_attr_for_each() performs arithmetic on void*
# Do not install python-crypto nor python3-crypto because they are too old
# Ubuntu<16.04 does not provide python-z3
RUN \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get -qq update && \
    apt-get install --no-install-recommends --no-install-suggests -qqy \
        clang \
        binutils-mingw-w64 \
        gcc-mingw-w64 \
        gcc-multilib \
        gdb \
        libc-dev \
        libc6-dev-i386 \
        libgmp-dev \
        libgtk-3-dev \
        libpulse-dev \
        linux-headers-generic \
        make \
        openjdk-7-jdk \
        pkg-config \
        python3 \
        python-argparse \
        wine && \
    apt-get clean

WORKDIR /shared
RUN ln -s shared/machines/run_shared_test.sh /run_shared_test.sh
COPY . /shared/

CMD ["/run_shared_test.sh"]

# make list-nobuild:
#    Global blacklist: latex%
#    In sub-directories:
#       c:
#       java/keystore: parse_jceks.py parse_pkcs12.py util_asn1.py
#       linux: enum_link_addrs sdl_v4l_video
#       python: cffi_example.py cffi_numpy.py udp_multihome.py z3_example.py
#       python/crypto: chacha20_poly1350_tests.py dhparam_tests.py dsa_tests.py ec_tests.py parse_openssl_enc.py rsa_tests.py
#       python/dnssec: verify_dnssec.py
#       verification: ackermann.vo
#    With gcc -m32:
#       Global blacklist: latex%
#       In sub-directories:
#          c: gmp_functions gtk_alpha_window
#          java/keystore: parse_jceks.py parse_pkcs12.py util_asn1.py
#          linux: enum_link_addrs pulseaudio_echo sdl_v4l_video
#          python: cffi_example.py cffi_numpy.py udp_multihome.py z3_example.py
#          python/crypto: chacha20_poly1350_tests.py dhparam_tests.py dsa_tests.py ec_tests.py parse_openssl_enc.py rsa_tests.py
#          python/dnssec: verify_dnssec.py
#          verification: ackermann.vo
#    Compilers:
#       gcc -m64: ok
#       gcc -m32: ok
#       clang -m64: ok
#       clang -m32: ok
#       musl-gcc: not working
#       x86_64-w64-mingw32-gcc: only compiling
#       i686-w64-mingw32-gcc: only compiling
