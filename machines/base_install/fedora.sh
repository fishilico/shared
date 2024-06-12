#!/usr/bin/env bash
# Install base packages on a Fedora distribution

# Abort immediately if something fails
set -e

# Filter categories:
# - Desktop environment (X11)
INSTALL_DESKTOP=false
# - GNOME Desktop manager
INSTALL_GDM=false
# - Lightdm Desktop manager
INSTALL_LIGHTDM=false
# - XFCE window manager
INSTALL_XFCE=false

while [ $# -ge 1 ]
do
    case "$1" in
        desktop)
            INSTALL_DESKTOP=true
            ;;
        gdm)
            INSTALL_DESKTOP=true
            INSTALL_GDM=true
            ;;
        lightdm)
            INSTALL_DESKTOP=true
            INSTALL_LIGHTDM=true
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

is_installed() {
    rpm -q "$1" > /dev/null 2>&1
}

# Install packages if they are not already installed
pkg() {
    local PKGNAME

    for PKGNAME in "$@"
    do
        if ! is_installed "$PKGNAME"
        then
            if ! is_root
            then
                echo "dnf --setopt=install_weak_deps=False install -y $PKGNAME"
            else
                dnf --setopt=install_weak_deps=False install -y "$PKGNAME"
            fi
        fi
    done
}

# Install a group of packages
grouppkg() {
    local GROUPNAME

    for GROUPNAME in "$@"
    do
        if ! (dnf group --quiet --installed list "$GROUPNAME" | grep ':' > /dev/null)
        then
            if ! is_root
            then
                echo "dnf --setopt=install_weak_deps=False install -y @$GROUPNAME"
            else
                dnf --setopt=install_weak_deps=False install -y "@$GROUPNAME"
            fi
        fi
    done
}

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
pkg gnupg2
pkg htop
pkg iotop
pkg jq
pkg keyutils
pkg less
pkg lsof
pkg most
pkg neovim
pkg progress
pkg psmisc
pkg pv
pkg pwgen
pkg rlwrap
pkg screen
pkg sequoia-sq
pkg sl
pkg strace
pkg sudo
pkg time
pkg tmux
pkg vim-enhanced
pkg zsh

# Hardware and TTY
pkg fwupd
pkg gpm
pkg kbd
pkg hwloc
pkg iw
pkg lshw
pkg monitor-edid
pkg pciutils
pkg tpm2-pkcs11
pkg tpm2-tools
pkg usbutils
pkg wireless-regdb
pkg wpa_supplicant

# Archives and filesystems
pkg btrfs-progs
pkg cryptsetup
pkg dosfstools
pkg lvm2
pkg mdadm
pkg mtools
pkg ntfs-3g
pkg unzip
pkg zip

# Network
pkg bind-utils
pkg bridge-utils
pkg curl
pkg dnsmasq
pkg fuse-sshfs
pkg ftp
pkg iftop
pkg iptables-nft
pkg ldns-utils
pkg lftp
pkg links
pkg mutt
pkg ndisc6
pkg net-tools
pkg nftables
pkg nmap
pkg nmap-ncat
pkg openssh
pkg postgresql
pkg rsync
pkg socat
pkg tcpdump
pkg telnet
pkg unbound
pkg wget
pkg whois

# Development
pkg clang
pkg clang-analyzer
pkg clang-tools-extra
pkg cmake
pkg fakeroot
pkg gcc
pkg gdb
pkg git
pkg highlight
pkg lcov
pkg libcap-ng-utils
pkg libcgroup-tools
pkg make
pkg pkgconf-pkg-config
pkg python2.7
pkg python3
pkg python3-isort
pkg python3-mypy
pkg ShellCheck

# Other
pkg cmatrix
pkg john
pkg sl

# Fedora-specific packages
pkg libselinux-utils
pkg policycoreutils-newrole
pkg policycoreutils-python-utils
pkg rpm-build
pkg rpm-sign
pkg rpmdevtools
pkg setools-console

if "$INSTALL_DESKTOP"
then
    # X11 server
    pkg rxvt-unicode
    pkg xorg-x11-server-Xorg
    pkg xscreensaver

    # Sound
    pkg alsa-utils
    #pkg paprefs # require pulseaudio
    pkg pavucontrol
    pkg pipewire-pulseaudio
    pkg pulseaudio-utils

    # Applications
    pkg arandr
    pkg baobab
    pkg bleachbit
    pkg chromium
    pkg eog
    pkg evince
    pkg file-roller
    pkg filezilla
    pkg gedit
    pkg gedit-plugins
    pkg gimp
    pkg gitk
    #pkg gksu # Removed because it is incompatible with Wayland, https://bugzilla.redhat.com/show_bug.cgi?id=1274451
    pkg gnome-system-monitor
    pkg gparted
    pkg graphviz
    pkg gvfs
    pkg keepassxc
    pkg kismet
    pkg libreoffice
    pkg meld
    pkg ModemManager
    pkg mupdf
    pkg network-manager-applet
    pkg NetworkManager
    pkg pandoc
    pkg parted
    pkg pdfpc
    pkg python3-pdfminer
    pkg qpdf
    #pkg texlive-full
    pkg tk
    pkg udisks
    pkg wireshark
    pkg xdg-utils
    pkg xsensors
    pkg xterm

    # Language
    pkg hunspell-en-GB
    pkg hunspell-en-US
    pkg hunspell-fr
    pkg mythes-en
    pkg mythes-fr

    # Require RPM Fusion repository
    #pkg ffmpeg
    #pkg vlc
fi

if "$INSTALL_GDM"
then
    pkg gdm
fi

if "$INSTALL_LIGHTDM"
then
    pkg gnome-themes-extra
    pkg lightdm
    pkg lightdm-gtk
fi

if "$INSTALL_XFCE"
then
    grouppkg xfce-desktop-environment
    pkg notification-daemon
    pkg tango-icon-theme
    pkg thunar-archive-plugin
    pkg thunar-media-tags-plugin
    pkg thunar-volman
    pkg tumbler
    pkg upower
    pkg xdg-user-dirs
    pkg xfce4-notifyd
    pkg xfce4-power-manager
    pkg xfce4-volumed
    pkg xfwm4-themes
fi
