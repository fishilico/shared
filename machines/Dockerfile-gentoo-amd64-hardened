FROM gentoo/stage3-amd64-hardened
LABEL Description="Gentoo Hardened with build dependencies for shared"

# Gentoo does not provide sci-mathematics/z3 with Python3 support:
#    https://gitweb.gentoo.org/repo/gentoo.git/tree/sci-mathematics/z3/z3-4.5.0.ebuild#n6
#    contains: PYTHON_COMPAT=( python2_7 )

# Override the language to force UTF-8 output
ENV LANG en_US.UTF-8

# Modify portage useflags and masks
RUN \
    echo 'USE="$USE python wayland"' >> /etc/portage/make.conf && \
    echo '>=x11-libs/cairo-1.14.12 X' >> /etc/portage/package.use/cairo && \
    echo '>=app-text/ghostscript-gpl-9.26 cups' >> /etc/portage/package.use/ghostscript-gpl && \
    echo '>=sys-devel/llvm-3.5.0 clang' >> /etc/portage/package.use/clang && \
    echo '>=media-libs/libsdl2-2.0.8 gles' >> /etc/portage/package.use/libsdl2 && \
    echo '>=media-libs/mesa-18.1.9 gles2' >> /etc/portage/package.use/mesa && \
    echo '>=media-plugins/alsa-plugins-1.0.29 pulseaudio' >> /etc/portage/package.use/pulseaudio && \
    echo '>=sys-apps/util-linux-2.32-r4 static-libs' >> /etc/portage/package.use/util-linux && \
    echo '>=sys-kernel/linux-firmware-20190514 linux-fw-redistributable no-source-code' >> /etc/portage/package.license

# llvm requires kernel sources in /usr/src/linux
# Merge llvm with MAKEOPTS="-j1", but its dependency "cmake" faster
# cf. https://forums.gentoo.org/viewtopic-t-1062974-start-0.html

# Installing dev-libs/gobject-introspection and x11-libs/gdk-pixbuf and some other packages fails with:
#  * ISE:_do_ptrace: ptrace(PTRACE_TRACEME, ..., 0x0000000000000000, 0x0000000000000000): Operation not permitted
# ERROR: can't resolve libraries to shared libraries: glib-2.0, gobject-2.0
# This is because Gentoo's build sandbox (sys-apps/sandbox) ptraces ldd (because it can't LDPRELOAD into it).
# Install it without the sandbox.
# cf. https://forums-web2.gentoo.org/viewtopic-t-1051762-view-next.html?sid=850e5ab46d3b0ba7b5b8ec32fa1566ba

# Clean-up downloaded distfiles in the end.
RUN \
    emerge --quiet --sync && \
    emerge dev-util/cmake sys-kernel/gentoo-sources && \
    MAKEOPTS='-j1' emerge sys-devel/llvm sys-devel/clang && \
    FEATURES='-usersandbox -sandbox' emerge \
        app-accessibility/at-spi2-core \
        dev-libs/atk \
        dev-libs/gobject-introspection \
        gnome-base/librsvg \
        media-libs/harfbuzz \
        x11-libs/gdk-pixbuf \
        x11-libs/gtk+:2 \
        x11-libs/gtk+:3 \
        x11-libs/pango && \
    emerge \
        dev-python/cffi \
        dev-python/gmpy \
        dev-python/numpy \
        dev-python/pycrypto \
        media-libs/libsdl2 \
        media-sound/pulseaudio \
        sci-mathematics/coq \
        sys-kernel/genkernel \
        virtual/jdk && \
    genkernel all && \
    rm -r /usr/portage/distfiles/ /var/tmp/portage/

#RUN emerge sys-libs/musl

# Try using crossdev for https://wiki.gentoo.org/wiki/Mingw
RUN emerge sys-devel/crossdev
RUN echo 'PORTDIR_OVERLAY="/usr/crossdev-overlay"' >> /etc/portage/make.conf
# TODO: add musl and MinGW (+ wine) from crossdev
#RUN crossdev --target x86_64-w64-mingw64
#RUN crossdev --target i686-w64-mingw32

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
#          c: gmp_functions gtk_alpha_window
#          java/keystore:
#          linux: enum_link_addrs pulseaudio_echo sdl_v4l_video
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
