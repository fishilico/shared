# -*- mode: ruby -*-
# vi: set ft=ruby :

# Run tests:
#    echo 'make -C /vagrant clean test' | vagrant ssh
# Run tests in Docker containers:
#    echo '/vagrant/machines/docker_test_all.sh' | vagrant ssh
# Run tests and record "make list-nobuild" output:
#    script -c "echo '/vagrant/machines/docker_test_all.sh' | vagrant ssh" dockers.log
#    ./machines/update_list_nobuild_from_log.py dockers.log

# In order to carry all possible Docker environments, at least 110 GB of storage
# is needed in the virtual machine. To expand a disk of a VM created using
# packer-arch and using libvirt, perform the following steps:
# * On the host, expand the QCow2 disk file:
#
#    cd /var/lib/libvirt/images
#    qemu-img resize shared_default.img +70G
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

# Make sure Python is installed
pacman -Qqi python > /dev/null || pacman --noconfirm -S python

# Install Docker and build Arch Linux Docker image
pacman -Qqi docker > /dev/null || pacman --noconfirm -S docker
systemctl enable --now docker
gpasswd -a vagrant docker
(docker images |grep -q '^archlinux ') || docker build -t archlinux /vagrant/machines/archlinux

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

  # Run the provisioning script
  config.vm.provision :shell, inline: $script

  # Ensure the build system works fine, and show what would run
  config.vm.provision :shell, inline: "make -C /vagrant list-nobuild"
end
