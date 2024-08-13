# When Arch Linux had no official Docker image, bootstrap from Debian
# Now Arch Linux provides base/archlinux:
#    https://hub.docker.com/r/base/archlinux/
#    https://github.com/archimg/archlinux
#
# Usage: docker build -t archlinux . && docker run --rm -ti archlinux
FROM debian:sid-slim
LABEL Description="Arch Linux base image"

# Steps:
# - Download the GPG key using a command documented on https://archlinux.org/download/
#   (this downloads https://openpgpkey.archlinux.org/.well-known/openpgpkey/archlinux.org/hu/9hy3wi4ewwiicomnjmhewifn6d1gi87i?l=pierre )
# - Install wget to be able to download and extract Arch Linux images
# - Download bootstrap image and extract it in /arch/root (cf. https://wiki.archlinux.org/index.php/Install_from_existing_Linux)
# - Switch over to Arch Linux, keeping Docker-special files
#   Removing /usr fails with some directories which are "not empty". Remove them in two steps.
# - Configure pacman, locales, etc.
# - Initialize pacman keyring
# - Remove packages which are not needed and install some useful base packages
RUN \
    set -x && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get -qq update && \
    apt-get install -qqy sq libarchive-tools wget && \
    apt-get clean && \
    mkdir /arch && cd /arch && \
    sq wkd get pierre@archlinux.org > release-key.pgp && \
    (wget -qO- https://mirror.rackspace.com/archlinux/iso/latest/sha256sums.txt | fgrep 'archlinux-bootstrap-x86_64.tar.zst' > sha256sums.txt) && \
    read -r SHA256 FILE < sha256sums.txt && \
    wget -q "https://mirror.rackspace.com/archlinux/iso/latest/$FILE" && \
    wget -q "https://mirror.rackspace.com/archlinux/iso/latest/$FILE.sig" && \
    sq verify --signer-cert release-key.pgp --detached "$FILE.sig" "$FILE" && \
    sha256sum -c sha256sums.txt && \
    bsdtar -xpf "$FILE" && \
    cd /arch/root.x86_64 && \
    (rm -r /usr/share/doc /usr/lib/x86_64-linux-gnu/perl-base ; true) && \
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
