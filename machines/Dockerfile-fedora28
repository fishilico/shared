FROM fedora:28
LABEL Description="Fedora 28 with build dependencies for shared"

# Override the language to force UTF-8 output
ENV LANG C.UTF-8

RUN \
    dnf update -q -y --setopt=deltarpm=false && \
    dnf install -q -y --setopt=deltarpm=false \
        clang \
        coq \
        elfutils-libelf-devel \
        gcc \
        gdb \
        glibc-devel.x86_64 \
        glibc-devel.i686 \
        gmp-devel.x86_64 \
        gmp-devel.i686 \
        gtk3-devel \
        java-11-openjdk-devel \
        kernel \
        kernel-devel \
        libmnl-devel.x86_64 \
        libmnl-devel.i686 \
        make \
        mingw32-gcc \
        mingw64-gcc \
        numpy \
        openssh \
        openssl \
        perl-Getopt-Long \
        perl-Term-ANSIColor \
        pkgconfig \
        pulseaudio-libs-devel \
        python3 \
        python3-cffi \
        python3-crypto \
        python3-devel \
        python3-gmpy2 \
        python3-numpy \
        python3-z3 \
        python2-cffi \
        python2-crypto \
        python2-devel \
        python2-gmpy2 \
        python2-z3 \
        SDL2-devel \
        which \
        wine && \
    dnf clean all

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
#          c: gtk_alpha_window openmp_matrix
#          java/keystore:
#          linux: pulseaudio_echo sdl_v4l_video
#          python:
#          python/crypto:
#          python/dnssec:
#          verification:
#    Compilers:
#       gcc -m64: ok
#       gcc -m32: ok
#       clang -m64: ok
#       clang -m32: ok
#       musl-gcc: not working
#       x86_64-w64-mingw32-gcc: ok
#       i686-w64-mingw32-gcc: ok
