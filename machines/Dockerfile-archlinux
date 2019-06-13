FROM archlinux/base
# Use https://github.com/docker/docker/blob/master/contrib/mkimage-arch.sh
# to build a local Arch Linux image, from an Arch Linux distribution.
# (Download https://raw.githubusercontent.com/docker/docker/master/contrib/mkimage-arch.sh
# and https://raw.githubusercontent.com/docker/docker/master/contrib/mkimage-arch-pacman.conf)
LABEL Description="Arch Linux with build dependencies for shared"

# Arch Linux no longer provides mingw-w64-gcc in its official repositories.
# Use Martchus ownstuff repo instead:
#   https://wiki.archlinux.org/index.php/unofficial_user_repositories#ownstuff
#   https://github.com/Martchus/PKGBUILDs

# Arch Linux no longer provides python2-z3, since 2019-03-19:
#   https://git.archlinux.org/svntogit/community.git/commit/?h=packages/z3&id=ce606b542b80ae8af30beda4c3838bd14818e51f
RUN \
    echo '[multilib]' >> /etc/pacman.conf && \
    echo 'Include = /etc/pacman.d/mirrorlist' >> /etc/pacman.conf && \
    echo '[ownstuff]' >> /etc/pacman.conf && \
    echo 'Server = http://martchus.no-ip.biz/repo/arch/$repo/os/$arch' >> /etc/pacman.conf && \
    echo 'SigLevel = Optional' >> /etc/pacman.conf && \
    pacman --noconfirm -Sy && \
    pacman --noconfirm -S \
        base-devel \
        clang \
        coq \
        gcc \
        gdb \
        gtk3 \
        jdk10-openjdk \
        kernel-headers-musl \
        libpulse \
        linux-headers \
        make \
        mingw-w64-gcc \
        musl \
        openssh \
        pkg-config \
        python \
        python-cffi \
        python-gmpy2 \
        python-numpy \
        python-pycryptodome \
        python-setuptools \
        python-z3 \
        python2 \
        python2-cffi \
        python2-numpy \
        python2-pycryptodome \
        python2-setuptools \
        sdl2 \
        which \
        wine && \
    (pacman --noconfirm -Sc ; rm -rf /var/cache/pacman/pkg/* )

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
#          linux: enum_link_addrs pulseaudio_echo
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
