FROM alpine:3.3
LABEL Description="Alpine Linux 3.3 with build dependencies for shared"

# Alpine does not provide: coq, mingw-w64, py3-z3
# Alpine<3.8 does not provide pulseaudio-dev
# Alpine<3.5 does not provide: py-numpy, py2-cffi, py3-cffi, py2-crypto, py3-crypto
# Alpine<3.4 does not provide sdl2-dev
RUN \
    apk --no-cache --update add \
        clang \
        gcc \
        gdb \
        gmp-dev \
        gtk+3.0-dev \
        iproute2 \
        libmnl-dev \
        linux-grsec-dev \
        linux-headers \
        llvm-dev \
        make \
        musl-dev \
        musl-utils \
        openjdk8 \
        openssh \
        python-dev \
        python3-dev && \
    rm -rf /var/cache/apk/*

# Add OpenJDK to $PATH
ENV JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /shared
RUN ln -s shared/machines/run_shared_test.sh /run_shared_test.sh
COPY . /shared/

CMD ["/run_shared_test.sh"]

# make list-nobuild:
#    Global blacklist: latex% linux/modules% windows%
#    In sub-directories:
#       c: x86-read_64b_regs_in_32b_mode
#       java/keystore: parse_jceks.py parse_pkcs12.py util_asn1.py
#       linux: pulseaudio_echo sdl_v4l_video
#       python: cffi_example.py cffi_numpy.py z3_example.py
#       python/crypto: chacha20_poly1350_tests.py dhparam_tests.py dsa_tests.py ec_tests.py parse_openssl_enc.py rsa_tests.py
#       python/dnssec: verify_dnssec.py
#       verification: ackermann.vo
#    Compilers:
#       gcc -m64: ok
#       gcc -m32: not working
#       clang -m64: ok
#       clang -m32: not working
#       musl-gcc: not working
#       x86_64-w64-mingw32-gcc: not working
#       i686-w64-mingw32-gcc: not working
