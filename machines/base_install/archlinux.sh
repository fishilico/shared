#!/usr/bin/env bash
# Install base packages on an Arch Linux distribution

# Abort immediately if something fails
set -e

# Filter categories:
# - Desktop environment (X11)
INSTALL_DESKTOP=false
# - Lightdm Desktop manager
INSTALL_LIGHTDM=false
# - Tools for program analysis
INSTALL_PRGANALYSIS_TOOLS=false
# - XFCE window manager
INSTALL_XFCE=false

while [ $# -ge 1 ]
do
    case "$1" in
        desktop)
            INSTALL_DESKTOP=true
            ;;
        lightdm)
            INSTALL_DESKTOP=true
            INSTALL_LIGHTDM=true
            ;;
        prganalysis-tools)
            INSTALL_PRGANALYSIS_TOOLS=true
            ;;
        xfce)
            INSTALL_DESKTOP=true
            INSTALL_XFCE=true
            ;;
        *)
            echo >&2 "Unknown selection $1"
            exit 1
            ;;
    esac
    shift
done

# Is this script running as root?
is_root() {
    [[ "$EUID" = "0" ]] || [ "$(id -u)" = "0" ]
}

# Find a usable user to build package without being root
BUILD_USER='nobody'
if ! is_root
then
    BUILD_USER="$(id -nu)"
elif [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != 'root' ]
then
    BUILD_USER="$SUDO_USER"
fi
echo "Using build user: $BUILD_USER"

# Install packages from the official repository
pkg() {
    local PKGNAMES PKG
    PKGNAMES=()
    for PKG
    do
        if ! pacman -Si "$PKG" > /dev/null ; then
            echo >&2 "Package $PKG is not in official repositories"
            return 1
        elif ! pacman -Qi "$PKG" > /dev/null ; then
            PKGNAMES+=("$PKG")
        fi
    done
    if [ -n "${PKGNAMES[*]}" ] ; then
        if ! is_root
        then
            echo "pacman -S --noconfirm ${PKGNAMES[*]}"
            return
        fi
        echo "Installing ${PKGNAMES[*]}"
        pacman -S --noconfirm "${PKGNAMES[@]}"
        return $?
    fi
}

# Install packages from the AUR repository
aurpkg() {
    local PKGNAMES PKG
    PKGNAMES=()
    for PKG
    do
        if pacman -Si "$PKG" > /dev/null 2>&1 ; then
            echo >&2 "Package $PKG is in official repositories, not in the AUR"
            return 1
        elif ! pacman -Qi "$PKG" > /dev/null ; then
            PKGNAMES+=("$PKG")
        fi
    done
    if [ -n "${PKGNAMES[*]}" ] ; then
        if ! is_root
        then
            echo "sudo -u $BUILD_USER trizen -S ${PKGNAMES[*]}"
            return
        fi
        echo "Installing for AUR ${PKGNAMES[*]}"
        sudo -u "$BUILD_USER" trizen -S "${PKGNAMES[@]}"
        return $?
    fi
}

# Install packages from groups in the official repository
grouppkg() {
    local PKG GROUP
    for GROUP
    do
        if pacman -Si "$GROUP" > /dev/null 2>&1 ; then
            echo >&2 "Group $GROUP is a package in official repositories, not a group"
            return 1
        elif ! pacman -Sg "$GROUP" > /dev/null ; then
            echo >&2 "Group $GROUP has not been found in official repositories"
            return 1
        else
            echo "Installing packages from group $GROUP..."
            # shellcheck disable=SC2046
            if ! pkg $(pacman -Sqg "$GROUP")
            then
                return 1
            fi
        fi
    done
}

# Update the package database
if is_root
then
    pacman -Sy
fi

# Bootstrap installation of trizen AUR helper
if ! pacman -Qi trizen > /dev/null
then
    TRIZEN_BOOTSTRAP_DIR="${TRIZEN_BOOTSTRAP_DIR:-/tmp/trizen_bootstrap_dir}"
    echo 'Download, build and install trizen...'
    if is_root
    then
        sudo -u "$BUILD_USER" mkdir -p "$TRIZEN_BOOTSTRAP_DIR"
        sudo -u "$BUILD_USER" git clone https://aur.archlinux.org/trizen.git "$TRIZEN_BOOTSTRAP_DIR"
        (cd "$TRIZEN_BOOTSTRAP_DIR" && sudo -u "$BUILD_USER" makepkg -si)
    else
        echo '... or not, as we are not root'
    fi
fi

# Essential packages
pkg attr
pkg audit
pkg base
pkg bash-completion
pkg bc
pkg binutils
pkg busybox
pkg ca-certificates
pkg ccze
pkg colordiff
pkg diffstat
pkg dos2unix
pkg file
pkg fortune-mod
pkg gnupg
pkg haveged
pkg highlight
pkg htop
pkg iotop
pkg jq
pkg less
pkg lsb-release
pkg lsof
pkg moreutils
pkg most
pkg neovim
pkg progress
pkg psmisc
pkg pv
pkg reptyr
pkg ripgrep
pkg rlwrap
pkg rng-tools
pkg screen
pkg sequoia-sq
pkg strace
pkg sudo
pkg time
pkg tmux
pkg vim
pkg zsh

# Hardware and TTY
pkg acpi
pkg acpi_call
pkg acpica
pkg bluez
pkg bluez-utils
pkg dmidecode
pkg efibootmgr
pkg fwupd
pkg gpm
pkg i2c-tools
pkg iw
pkg kbd
pkg libfido2
pkg lm_sensors
pkg lshw
pkg pciutils
pkg picocom
pkg read-edid
pkg smartmontools
pkg tpm2-pkcs11
pkg tpm2-tools
pkg tpm2-tss-engine
pkg usbutils
pkg wireless-regdb
pkg wireless_tools
pkg wpa_supplicant

# Archives and filesystems
pkg btrfs-progs
pkg cabextract
pkg cpio
pkg cryfs
pkg cryptsetup
pkg dosfstools
pkg exfat-utils
pkg ext4magic
pkg innoextract
pkg lvm2
pkg lzop
pkg mdadm
pkg mtd-utils
pkg mtools
pkg ntfs-3g
pkg p7zip
pkg squashfs-tools
pkg unrar
pkg unzip
pkg zip

# Network
pkg bind
pkg bridge-utils
pkg curl
pkg cyrus-sasl-gssapi
pkg dhclient
pkg dnsmasq
pkg fail2ban
pkg firejail
pkg hping
pkg iftop
pkg inetutils
pkg iptables-nft
pkg iputils
pkg ldns
pkg lftp
pkg links
pkg mariadb-clients
pkg mtr
pkg mutt
pkg ndisc6
pkg net-snmp
pkg net-tools
pkg nftables
pkg nmap
pkg openbsd-netcat
pkg openldap
pkg openssh
pkg postgresql-libs
pkg proxychains-ng
pkg rsync
pkg smbclient
pkg socat
pkg sqlmap
pkg sshfs
pkg stubby
pkg tcpdump
#pkg tor
pkg torsocks
pkg traceroute
pkg unbound
pkg wget
pkg whois
pkg wireguard-tools
pkg wireshark-cli

# Development
grouppkg linux-tools
pkg autoconf-archive
pkg base-devel
pkg bat
pkg bison
pkg check
pkg clang
pkg cmake
pkg devtools
pkg ed
pkg fakechroot
pkg fakeroot
pkg flex
pkg gdb
pkg git
pkg go
pkg help2man
pkg hexyl
pkg ipython
pkg libcap-ng
pkg linux-hardened-headers
pkg linux-headers
pkg ltrace
pkg multilib-devel
pkg mypy
pkg nodejs
pkg npm
pkg pkgconf
pkg pwgen
pkg pypy
pkg pypy3
pkg python
pkg ruby
pkg ruby-irb
pkg ruby-rake
pkg rustup
pkg sbt
pkg shellcheck
pkg yarn

# Intel x86 CPU
if [ "$(uname -m)" = 'x86_64' ]
then
    pkg intel-ucode
    pkg iucode-tool
    pkg x86_energy_perf_policy
fi

# Other
pkg cmatrix
pkg figlet
pkg john
pkg lolcat
pkg sl

# Arch Linux-specific packages
pkg asp
pkg aurphan
pkg pacman-contrib

if "$INSTALL_DESKTOP"
then
    # X11 server
    grouppkg xorg
    grouppkg xorg-drivers
    pkg rxvt-unicode
    pkg wmctrl
    pkg xpra
    pkg xscreensaver
    pkg xsel
    pkg xterm

    # Fonts
    pkg gnu-free-fonts
    pkg ttf-bitstream-vera
    pkg ttf-cascadia-code
    pkg ttf-dejavu
    pkg ttf-droid
    pkg ttf-fantasque-sans-mono
    pkg ttf-fira-code
    pkg ttf-fira-mono
    pkg ttf-fira-sans
    pkg ttf-font-awesome
    pkg ttf-inconsolata
    pkg ttf-liberation
    pkg ttf-ubuntu-font-family
    aurpkg ttf-vlgothic

    # Sound
    pkg alsa-utils
    pkg audacity
    pkg paprefs
    pkg pavucontrol
    pkg pulseaudio

    # Smartcard and YubiKey
    pkg ccid
    pkg opensc
    pkg pcsc-tools
    pkg yubikey-manager
    pkg yubikey-personalization
    pkg yubikey-personalization-gui

    # Applications
    pkg arandr
    pkg baobab
    pkg bleachbit
    pkg cheese
    pkg chromium
    pkg eog
    pkg evince
    pkg ffmpeg
    pkg file-roller
    pkg filezilla
    pkg firefox
    pkg freerdp
    pkg gedit
    pkg gedit-plugins
    pkg gimp
    pkg gnome-mahjongg
    pkg gnome-system-monitor
    pkg gparted
    pkg graphviz
    pkg gtk3
    pkg gvfs
    pkg gvfs-smb
    pkg imagemagick
    pkg inkscape
    pkg keepass
    pkg kismet
    pkg libreoffice-fresh
    pkg libvncserver
    pkg meld
    pkg modemmanager
    pkg mupdf
    pkg mupdf-tools
    pkg network-manager-applet
    pkg networkmanager
    pkg networkmanager-openvpn
    pkg networkmanager-strongswan
    pkg pandoc-cli
    pkg parted
    pkg pdfpc
    pkg python-pdfminer
    pkg qpdf
    pkg rdesktop
    pkg recordmydesktop
    pkg remmina
    pkg sdl2
    pkg simple-scan
    pkg sox
    pkg sqlitebrowser
    pkg tk
    pkg udisks2
    pkg vinagre
    pkg vlc
    pkg wireshark-qt
    pkg x11vnc
    pkg xdg-utils
    pkg xdot
    pkg xsensors
    pkg xterm
    pkg youtube-dl
    pkg zenity

    aurpkg burpsuite
    aurpkg restview
    aurpkg trickle

    # Language
    pkg hunspell-en_gb
    pkg hunspell-en_us
    pkg hunspell-fr
    pkg mythes-en
    pkg mythes-fr

    # Power management for laptops
    pkg tlp
    pkg tp_smapi

    # Multilib repo
    pkg wine wine-gecko wine-mono winetricks

    # MinGW64
    pkg mingw-w64-binutils mingw-w64-gcc

    # Optional
    #pkg gnome-keyring
    #pkg virtualbox
    #pkg virtualbox-host-dkms
    #pkg virtualbox-guest-iso
fi

if "$INSTALL_LIGHTDM"
then
    pkg lightdm
    pkg lightdm-gtk-greeter
fi

if "$INSTALL_XFCE"
then
    grouppkg xfce4
    grouppkg xfce4-goodies
fi

if "$INSTALL_PRGANALYSIS_TOOLS"
then
    pkg aarch64-linux-gnu-binutils
    pkg aarch64-linux-gnu-gcc
    pkg aarch64-linux-gnu-gdb
    pkg aarch64-linux-gnu-glibc
    pkg aarch64-linux-gnu-linux-api-headers
    pkg aircrack-ng
    pkg ansible
    pkg ansible-lint
    pkg arduino-avr-core
    pkg arm-none-eabi-binutils
    pkg arm-none-eabi-gcc
    pkg arm-none-eabi-gdb
    pkg arm-none-eabi-newlib
    pkg binwalk
    pkg clinfo
    pkg codespell
    pkg cppcheck
    pkg docker-compose
    pkg earlyoom
    pkg flake8
    pkg ghidra
    pkg hashcat
    pkg hashcat-utils
    pkg hydra
    pkg iaito
    pkg impacket
    pkg ipcalc
    pkg ipv6calc
    pkg jre-openjdk
    pkg lcov
    pkg libnfc
    pkg libvirt
    #pkg lxc
    #pkg mariadb
    pkg maven
    pkg medusa
    pkg metasploit
    pkg openocd
    pkg perl-net-dns
    pkg php
    pkg php-sqlite
    pkg podman
    pkg python-argon2_cffi
    pkg python-gmpy2
    pkg python-isort
    pkg python-kaitaistruct
    pkg python-keystone
    pkg python-lxml
    pkg python-matplotlib
    pkg python-numpy
    pkg python-passlib
    pkg python-pew
    pkg python-pillow
    pkg python-pipenv
    pkg python-pwntools
    pkg python-pycryptodome
    pkg python-pyelftools
    pkg python-pyflakes
    pkg python-pylint
    pkg python-pyopenssl
    pkg python-pyqtgraph
    pkg python-pyserial
    pkg python-pyusb
    pkg python-qrcode
    pkg python-requests
    pkg python-scapy
    pkg python-scipy
    pkg python-sphinx
    pkg python-sympy
    pkg python-unicorn
    pkg python-yaml
    pkg python-z3-solver
    pkg qemu-desktop
    pkg qemu-system-x86
    pkg qemu-user-static
    pkg radare2
    pkg ropgadget
    pkg sagemath
    pkg samba
    pkg sleuthkit
    pkg smbnetfs
    pkg sshpass
    pkg upx
    pkg vagrant
    pkg volatility3
    pkg wabt
    pkg zbar

    grouppkg texlive
    pkg texlive-langfrench

    aurpkg android-apktool
    aurpkg arm-linux-gnueabihf-binutils
    aurpkg arm-linux-gnueabihf-gcc
    aurpkg arm-linux-gnueabihf-glibc
    aurpkg arm-linux-gnueabihf-linux-api-headers
    #aurpkg beignet  # For using OpenCL on some Intel iGPU
    #aurpkg bochs
    aurpkg bluez-hcitool
    aurpkg bluez-rfcomm
    aurpkg coccinelle
    aurpkg dex2jar
    aurpkg ffdec
    aurpkg ilspymono-git
    aurpkg jd-gui
    aurpkg kaitai-struct-compiler
    aurpkg kaitai-struct-visualizer
    aurpkg libcgroup
    aurpkg msodbcsql
    aurpkg patator
    aurpkg pngcheck
    aurpkg proot
    aurpkg python-dlint
    aurpkg python-roca-detect
    aurpkg python-uncompyle6
    #aurpkg python-pwntools-git
    aurpkg pyzbar
    aurpkg sasquatch
    aurpkg selinux-python
    aurpkg setools
    aurpkg stegsolve
    aurpkg tpm-tools
    aurpkg uefitool-git
    aurpkg uefitool-ng-git

    # Humour
    aurpkg gti

    # Web analysis
    pkg sslscan
    pkg zaproxy
    aurpkg dirbuster
    aurpkg sslyze
    aurpkg wfuzz
fi
