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
pkg highlight
pkg htop
pkg iotop
pkg jq
pkg less
pkg lsb-release
pkg lsof
pkg moreutils
pkg most
pkg psmisc
pkg pv
pkg rlwrap
pkg screen
pkg strace
pkg sudo
pkg time
pkg tmux
pkg vim
pkg zsh

# Hardware and TTY
pkg acpi
pkg efibootmgr
pkg gpm
pkg iw
pkg kbd
pkg lm_sensors
pkg lshw
pkg pciutils
pkg picocom
pkg smartmontools
pkg usbutils
pkg wireless_tools
pkg wpa_supplicant

# Archives and filesystems
pkg btrfs-progs
pkg cabextract
pkg cpio
pkg cryptsetup
pkg dosfstools
pkg exfat-utils
pkg extundelete
pkg innoextract
pkg lvm2
pkg lzop
pkg mdadm
pkg mtools
pkg ntfs-3g
pkg p7zip
pkg unrar
pkg unzip
pkg zip
aurpkg sasquatch

# Network
pkg arptables
pkg bind-tools
pkg bridge-utils
pkg curl
pkg dnsmasq
pkg ebtables
pkg hping
pkg iftop
pkg inetutils
pkg iptables
pkg iputils
pkg ldns
pkg lftp
pkg links
pkg mariadb-clients
pkg mutt
pkg ndisc6
pkg net-snmp
pkg net-tools
pkg nftables
pkg nmap
pkg openbsd-netcat
pkg openldap
pkg openssh
pkg rsync
pkg smbclient
pkg socat
pkg sqlmap
pkg sshfs
pkg stubby
pkg tcpdump
pkg unbound
pkg wget
pkg whois
pkg wireshark-cli

# Development
grouppkg base-devel
grouppkg multilib-devel
pkg clang
pkg cmake
pkg fakeroot
pkg gdb
pkg git
pkg go
pkg ipython
pkg libcap-ng
pkg linux-headers
pkg ltrace
pkg php
pkg pkgconf
pkg pypy
pkg pypy3
pkg python
pkg python2
pkg ruby
pkg ruby-irb
pkg rustup
pkg sbt
pkg shellcheck
aurpkg libcgroup

# Intel x86 CPU
if [ "$(uname -m)" = 'x86_64' ]
then
    pkg intel-ucode
    pkg iucode-tool
fi

# Other
pkg cmatrix
pkg john
pkg lolcat
pkg sl
aurpkg earlyoom
aurpkg gti

# Arch Linux-specific packages
pkg asp
pkg aurphan
pkg pacman-contrib

if "$INSTALL_DESKTOP"
then
    # X11 server
    grouppkg xorg
    pkg rxvt-unicode
    pkg wmctrl
    pkg xscreensaver
    pkg xsel
    pkg xterm

    # Fonts
    pkg ttf-bitstream-vera
    pkg ttf-dejavu
    pkg ttf-droid
    pkg ttf-fantasque-sans-mono
    pkg ttf-freefont
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

    # Applications
    pkg arandr
    pkg baobab
    pkg bleachbit
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
    pkg gnome-system-monitor
    pkg gparted
    pkg graphviz
    pkg gtk-recordmydesktop
    pkg gtk3
    pkg gvfs
    pkg keepass
    pkg kismet
    pkg libreoffice-fresh
    pkg meld
    pkg modemmanager
    pkg mupdf
    pkg network-manager-applet
    pkg networkmanager
    pkg pandoc
    pkg parted
    pkg pdfpc
    pkg qpdf
    pkg rdesktop
    pkg remmina
    pkg sdl2
    pkg simple-scan
    pkg sqlitebrowser
    pkg tk
    pkg udisks2
    pkg vinagre
    pkg vlc
    pkg wireshark-gtk
    pkg xdg-utils
    pkg xsensors
    pkg xterm

    aurpkg burpsuite
    aurpkg restview

    # Language
    pkg hunspell-en_GB
    pkg hunspell-en_US
    pkg hunspell-fr
    pkg mythes-en
    pkg mythes-fr

    # Multilib repo
    pkg wine wine_gecko wine-mono winetricks

    # MinGW64
    aurpkg mingw-w64-binutils mingw-w64-gcc

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
    pkg arduino-avr-core
    pkg arm-none-eabi-binutils
    pkg arm-none-eabi-gcc
    pkg binwalk
    pkg codespell
    pkg cppcheck
    #pkg docker-compose
    pkg flake8
    pkg ipcalc
    pkg ipv6calc
    pkg jre10-openjdk
    pkg libvirt
    #pkg lxc
    #pkg mariadb
    pkg metasploit
    pkg python-kaitaistruct
    pkg python-lxml
    pkg python-numpy
    pkg python-pew
    pkg python-pillow
    pkg python-pycryptodome
    pkg python-pyelftools
    pkg python-pyflakes
    pkg python-pylint
    pkg python-pyopenssl
    pkg python-pyusb
    pkg python-qrcode
    pkg python-scapy
    pkg python-scipy
    pkg python-sphinx
    pkg python-unicorn
    pkg python-yaml
    pkg python-z3
    pkg python2-pillow
    pkg python2-scapy
    pkg python2-yara
    pkg qemu
    pkg qemu-arch-extra
    pkg radare2
    pkg radare2-cutter
    pkg ropgadget
    pkg sagemath
    pkg vagrant
    pkg volatility
    pkg wabt

    aurpkg android-apktool
    aurpkg dex2jar
    aurpkg ilspymono-git
    aurpkg jd-gui
    aurpkg kaitai-struct-compiler
    aurpkg kaitai-struct-visualizer
    aurpkg openocd
    aurpkg python-roca-detect
    aurpkg python-uncompyle6
    aurpkg setools
    aurpkg selinux-python
    aurpkg stegsolve

    # Web analysis
    pkg sslscan
    pkg zaproxy
    aurpkg dirbuster
    aurpkg sslyze
    aurpkg wfuzz
fi
