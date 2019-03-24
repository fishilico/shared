FROM alpine:3.8
LABEL Description="Alpine Linux 3.8 with build dependencies for shared"

# Alpine does not provide coq, mingw-w64, and py3-z3 is in testing
RUN \
    apk --no-cache --update add \
        clang \
        clang-dev \
        gcc \
        gdb \
        gmp-dev \
        gtk+3.0-dev \
        iproute2 \
        libmnl-dev \
        libressl \
        linux-vanilla-dev \
        linux-headers \
        llvm-dev \
        make \
        musl-dev \
        musl-utils \
        nss \
        openjdk8 \
        openssh \
        pulseaudio-dev \
        py-numpy \
        py2-cffi \
        py2-crypto \
        py3-cffi \
        py3-crypto \
        python2-dev \
        python3-dev \
        sdl2-dev && \
    rm -rf /var/cache/apk/*

# Add OpenJDK to $PATH
ENV JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /shared
RUN ln -s shared/machines/run_shared_test.sh /run_shared_test.sh
COPY . /shared/

CMD ["/run_shared_test.sh"]

# make list-nobuild:
#    Global blacklist: latex% windows%
#    In sub-directories:
#       c: x86-read_64b_regs_in_32b_mode
#       java/keystore:
#       linux:
#       python: z3_example.py
#       python/crypto:
#       python/dnssec:
#       verification: ackermann.vo
#    Compilers:
#       gcc -m64: ok
#       gcc -m32: not working
#       clang -m64: ok
#       clang -m32: not working
#       musl-gcc: not working
#       x86_64-w64-mingw32-gcc: not working
#       i686-w64-mingw32-gcc: not working
