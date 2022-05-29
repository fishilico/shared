# -*- mode: ruby -*-
# vi: set ft=ruby :

# Run tests:
#    echo 'make -C /vagrant clean test' | vagrant ssh
# Run tests in Docker containers:
#    echo '/vagrant/machines/docker_test_all.sh' | vagrant ssh
# Run tests and record "make list-nobuild" output:
#    script -c "echo '/vagrant/machines/docker_test_all.sh' | vagrant ssh" dockers.log
#    ./machines/update_list_nobuild_from_log.py dockers.log

# In order to carry all possible Docker environments, at least 200 GB of storage
# is needed in the virtual machine. To expand a disk of a VM created using
# packer-arch and using libvirt, perform the following steps:
# * On the host, expand the QCow2 disk file:
#
#    cd /var/lib/libvirt/images
#    qemu-img resize shared_default.img +160G
#    qemu-img info shared_default.img |grep 'virtual size:'
#
# * Power on the VM.
# * On the guest, expand the partition table:
#
#    fdisk /dev/vda
#    # Delete the first (and only) partition.
#    # Create a new partition, starting at offset 2048, without removing the
#    # ext4 partition signature.
#
# * On the guest, make the partition bootable again (-i installs Syslinux, -a
#   sets the boot flag, -m installs Syslinux MBR):
#
#    pacman -S gptfdisk
#    sgdisk /dev/vda --attributes=1:set:2
#    syslinux-install_update -i -a -m
#
# * Reboot the VM.
# * Resize the ext4 filesystem on the guest to fill the new space:
#
#    resize2fs /dev/vda1

# Provisioning script: update the system, install docker and create an Arch Linux Docker image
$script = <<SCRIPT
timedatectl set-timezone UTC
sed -i -e 's/^#\\?MAKEFLAGS=.*/MAKEFLAGS="-j\\$(nproc)"/' /etc/makepkg.conf

# Update archlinux-keyring before the other packages in order to make sure the
# recently-added packagers are known.
pacman --noconfirm -Sy
if [ "$(pacman -Qi archlinux-keyring | grep '^Version')" != "$(pacman -Si archlinux-keyring | grep '^Version')" ]
then
    pacman --noconfirm -S archlinux-keyring
fi
pacman --noconfirm -Su

# Make sure Python, Docker and other needed packages are installed
for PKG in docker gcc make pkgconf python
do
    pacman -Qqi "$PKG" > /dev/null || pacman --noconfirm -S "$PKG"
done

# Install Docker and build Arch Linux Docker image
systemctl enable --now docker
gpasswd -a vagrant docker
(docker images |grep -q '^archlinux ') || su vagrant -c 'docker build -t archlinux /vagrant/machines/archlinux'

# Use vsyscall=emulate on the command line, for Debian 7 Wheezy
if [ -e /boot/syslinux/syslinux.cfg ] && ! grep vsyscall=emulate /boot/syslinux/syslinux.cfg > /dev/null
then
    sed -i -e 's/^\\(\\s*APPEND\\s.*\\)/\\1 vsyscall=emulate/' /boot/syslinux/syslinux.cfg
    syslinux-install_update -i -a -m
fi

# Make sure that the number of kernel file handles stays reasonable by defining
# a limit in /proc/sys/fs/file-max
echo 'fs.file-max = 10000' > /etc/sysctl.d/99-sane-open-files-limit.conf
SCRIPT

# Install an ARM chroot with Debian sid
$arm_chroot_script = <<SCRIPT
# Install Qemu static, in order to run foreign architectures on Arch Linux
if ! pacman -Qqi qemu-user-static > /dev/null
then
    pacman -Qqi git > /dev/null || pacman --noconfirm -S git
    pacman -Qqi patch > /dev/null || pacman --noconfirm -S patch
    pacman -Qqi fakeroot > /dev/null || pacman --noconfirm -S fakeroot

    # Install its dependencies
    if ! pacman -Qqi glib2-static > /dev/null
    then
        sudo -u vagrant git clone https://aur.archlinux.org/glib2-static.git AUR_glib2-static
        (cd AUR_glib2-static && sudo -u vagrant makepkg -si --noconfirm --nocheck) && rm -rf AUR_glib2-static
    fi
    if ! pacman -Qqi pcre-static > /dev/null
    then
        sudo -u vagrant git clone https://aur.archlinux.org/pcre-static.git AUR_pcre-static
        (cd AUR_pcre-static && sudo -u vagrant makepkg -si --noconfirm --skippgpcheck) && rm -rf AUR_pcre-static
    fi
    sudo -u vagrant git clone https://aur.archlinux.org/qemu-user-static.git AUR_qemu-user-static
    (cd AUR_qemu-user-static && sudo -u vagrant makepkg -si --noconfirm --skippgpcheck) && rm -rf AUR_qemu-user-static
fi

# Install a binfmt handler for ARM
# cf. https://aur.archlinux.org/cgit/aur.git/tree/qemu-static.conf?h=binfmt-qemu-static
if ! [ -f /etc/binfmt.d/qemu-arm.conf ]
then
    echo ':qemu-arm:M::\\x7fELF\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x28\\x00:\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff:/usr/bin/qemu-arm-static:' > /etc/binfmt.d/qemu-arm.conf
    systemctl restart systemd-binfmt.service
fi

# Install debootstrap and Debian keyring
pacman -Qqi debootstrap > /dev/null || pacman --noconfirm -S debootstrap
pacman -Qqi debian-archive-keyring > /dev/null || pacman --noconfirm -S debian-archive-keyring
# Install arch-install-scripts for "arch-chroot"
pacman -Qqi arch-install-scripts > /dev/null || pacman --noconfirm -S arch-install-scripts
if ! [ -d arm-debian ]
then
    # Bootstrap the ARM-Debian chroot, copying qemu-arm-static inside too
    mkdir -p arm-debian/usr/bin
    cp -v /usr/bin/qemu-arm-static arm-debian/usr/bin/
    debootstrap --arch=armel --force-check-gpg sid arm-debian

    # Add a helper to enter the chroot
    [ -d bin ] || sudo -u vagrant mkdir bin
    sudo -u vagrant tee bin/enter-arm-debian > /dev/null << EOF
#!/bin/bash
if [ "\\\$(id -u)" != 0 ]
then
    # Change to vagrant user inside the chroot
    if [ "\\\$#" -eq 0 ]
    then
        set su vagrant
    else
        set su vagrant -c "\\\$*"
    fi
elif [ "\\\$#" -eq 0 ]
then
    # Run bash by default, as root
    set bash
fi
exec sudo arch-chroot /home/vagrant/arm-debian /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin "\\\$@"
EOF
    chmod +x bin/enter-arm-debian

    # Install the same packages as the last Debian machine, but without the x86-specific packages
    sed -n '/^RUN \\\\/,/[^\\\\]\$/{p}' /vagrant/machines/Dockerfile-debian10-buster | \\
        tail -n +2 | \\
        sed 's/dpkg --add-architecture i386/true/' | \\
        sed 's/ gcc-multilib / gcc /g' | \\
        sed 's/ libc6-dev-i386 / /g' | \\
        sed 's/ linux-headers-amd64 / /g' | \\
        sed 's/ wine64 / /g' | \\
        arch-chroot arm-debian /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin DEBIAN_FRONTEND=noninteractive sh -x

    # Add vagrant user
    arch-chroot arm-debian /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin useradd -m --uid 1000 --user-group --shell /bin/bash vagrant
fi

# Bind-mount /vagrant
if ! grep -q '^/vagrant /home/vagrant/arm-debian ' /etc/fstab
then
    echo '/vagrant /home/vagrant/arm-debian/vagrant none bind 0 0' >> /etc/fstab
    mkdir -p arm-debian/vagrant
    mount arm-debian/vagrant
fi

# Upgrade Debian
arch-chroot arm-debian apt-get update
arch-chroot arm-debian /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin apt-get -y dist-upgrade
SCRIPT

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  # Use Arch Linux Vagrant Base box
  # https://wiki.archlinux.org/index.php/Vagrant#Base_Boxes_for_Vagrant
  # For example with https://github.com/elasticdog/packer-arch and libvirt:
  #    cd packer-arch
  #    ./wrapacker -p libvirt
  #    vagrant box add archlinux output/packer_arch_libvirt.box
  config.vm.box = "archlinux"

  config.vm.provider :libvirt do |v|
    v.cpus = 4
    v.memory = 4096
  end

  # Run the provisioning scripts
  config.vm.provision :shell, inline: $script
  config.vm.provision :shell, inline: $arm_chroot_script

  # Ensure the build system works fine, and show what would run
  config.vm.provision :shell, inline: "make -C /vagrant list-nobuild"
end
