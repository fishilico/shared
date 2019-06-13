FROM sabayon/base-amd64
LABEL Description="Sabayon Linux with build dependencies for shared"

# Sabayon does not provide: mingw64, musl, z3

# Override the language settings, as Entropy (command "equo") requires a UTF-8 console
ENV LANG en_US.UTF-8

# We need to accept several licenses in order to install packages, by using the
# file used by Sabayon's package manager, Entropy.
# The list of accepted licenses lies in Entropy SQLite database,
# /var/lib/entropy/client/database/amd64/equo.db (table licenses_accepted).
RUN \
    ( \
        echo 'AGPL-3' && \
        echo 'BSD-with-attribution' && \
        echo 'CC0-1.0' && \
        echo 'CC-BY-SA-3.0' && \
        echo 'CC-PD' && \
        echo 'FraunhoferFDK' && \
        echo 'GPL-1+' && \
        echo 'GPL-2-with-classpath-exception' && \
        echo 'HPND' && \
        echo 'IJG' && \
        echo 'Ispell' && \
        echo 'LGPL-2-with-linking-exception' && \
        echo 'LGPL-2.1-with-linking-exception' && \
        echo 'LLVM-Grant' && \
        echo 'MPL-2.0' && \
        echo 'Old-MIT' && \
        echo 'PCRE' && \
        echo 'RSA' && \
        echo 'SGI-B-2.0' && \
        echo 'SMAIL' && \
        echo 'UoI-NCSA' && \
        echo 'gsm' && \
        echo 'inner-net' && \
        echo 'libpng' && \
        echo 'libpng2' && \
        echo 'libtiff' && \
        echo 'linux-firmware' && \
        echo 'no-source-code' && \
        echo 'rc' && \
        echo 'rdisc' && \
        true) >> /etc/entropy/packages/license.accept && \
    equo update && \
    equo install \
        dev-python/cffi \
        dev-python/gmpy \
        dev-python/pycrypto \
        dev-python/numpy \
        media-libs/libsdl2 \
        media-sound/pulseaudio \
        sci-mathematics/coq \
        sys-devel/clang \
        sys-devel/gcc \
        sys-kernel/linux-sabayon \
        sys-kernel/sabayon-sources \
        virtual/jdk \
        x11-libs/gtk+ && \
    equo cleanup && \
    equo cache clean

WORKDIR /shared
RUN ln -s shared/machines/run_shared_test.sh /run_shared_test.sh
COPY . /shared/

CMD ["/run_shared_test.sh"]

# make list-nobuild:
#    Global blacklist: latex% windows%
#    In sub-directories:
#       c:
#       java/keystore:
#       linux:
#       python: z3_example.py
#       python/crypto:
#       python/dnssec:
#       verification:
#    With gcc -m32:
#       Global blacklist: latex% windows%
#       In sub-directories:
#          c: gtk_alpha_window
#          java/keystore:
#          linux: enum_link_addrs
#          python: z3_example.py
#          python/crypto:
#          python/dnssec:
#          verification:
#    Compilers:
#       gcc -m64: ok
#       gcc -m32: ok
#       clang -m64: ok
#       clang -m32: ok
#       musl-gcc: not working
#       x86_64-w64-mingw32-gcc: not working
#       i686-w64-mingw32-gcc: not working
