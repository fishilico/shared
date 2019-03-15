# When Arch Linux had no official Docker image, bootstrap from Debian
# Now Arch Linux provides base/archlinux:
#    https://hub.docker.com/r/base/archlinux/
#    https://github.com/archimg/archlinux
#
# Usage: docker build -t archlinux . && docker run --rm -ti archlinux
FROM debian:sid-slim
LABEL Description="Arch Linux base image"

# PGP key of Pierre Schmitz from https://pgp.mit.edu/pks/lookup?op=get&search=0x7F2D434B9741E8AC
# cf. https://www.archlinux.org/master-keys/
COPY 4AA4767BBC9C4B1D18AE28B77F2D434B9741E8AC.asc /etc/archlinux-signing-key.asc

# Steps:
# - Install wget to be able to download and extract Arch Linux images
# - Download bootstrap image and extract it in /arch/root (cf. https://wiki.archlinux.org/index.php/Install_from_existing_Linux)
# - Switch over to Arch Linux, keeping Docker-special files
# - Configure pacman, locales, etc.
# - Initialize pacman keyring
# - Remove packages which are not needed and install some useful base packages
RUN \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get -qq update && \
    apt-get install -qqy bsdtar gnupg wget && \
    apt-get clean && \
    gpg --import /etc/archlinux-signing-key.asc && \
    mkdir /arch && cd /arch && \
    (wget -qO- https://mirror.rackspace.com/archlinux/iso/latest/sha1sums.txt | fgrep 'x86_64.tar' > sha1sum.txt) && \
    read -r SHA1 FILE < sha1sum.txt && \
    wget -q "https://mirror.rackspace.com/archlinux/iso/latest/$FILE" && \
    wget -q "https://mirror.rackspace.com/archlinux/iso/latest/$FILE.sig" && \
    gpg --verify "$FILE.sig" "$FILE" && \
    sha1sum -c sha1sum.txt && \
    bsdtar -xpzf "$FILE" && \
    cd /arch/root.x86_64 && \
    rm -r /bin /lib* /opt /root /sbin /srv /usr /var && \
    LD_LIBRARY_PATH=/arch/root.x86_64/lib /arch/root.x86_64/lib/ld-linux-x86-64.so.* bin/mv bin lib* opt root sbin srv usr var / && \
    find /etc/* -maxdepth 0 -not \( -name resolv.conf -o -name hostname -o -name hosts \) -exec rm -r {} + && \
    rm /arch/root.x86_64/etc/hosts /arch/root.x86_64/etc/resolv.conf && \
    mv /arch/root.x86_64/etc/* /etc && \
    cd / && \
    rm -r /arch && \
    echo 'Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist && \
    ln -sf ../usr/share/zoneinfo/UTC /etc/localtime && \
    echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen && \
    pacman-key --init && \
    pacman-key --populate archlinux && \
    pacman --noconfirm -Rn arch-install-scripts && \
    pacman --noconfirm -Syu diffutils gawk grep procps-ng sed tar which && \
    (pkill gpg-agent ; true) && \
    pacman --noconfirm -Sc && \
    rm -r /usr/share/info/* /usr/share/man/* && \
    rm -r /var/cache/pacman/pkg/* /var/lib/pacman/sync/* /var/log/*.log

CMD ["/usr/bin/bash"]
