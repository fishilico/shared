#!/usr/bin/env dash
# Install base packages on a Debian-based distribution (Debian, Ubuntu, etc.)

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
    [ "$(id -u)" = "0" ]
}

is_installed() {
    dpkg -s "$1" > /dev/null 2>&1
}

is_available() {
    LANG=C apt-cache show "$1" 2> /dev/null |grep '^Package:' > /dev/null
}

# Use apt if running on a tty
if [ -t 1 ] && [ -x /usr/bin/apt ]
then
    APT=apt
else
    APT=apt-get
fi

# Install packages if they are not already installed
pkg() {
    local PKGNAME

    for PKGNAME in "$@"
    do
        if ! is_installed "$PKGNAME"
        then
            if ! is_root
            then
                echo "$APT install -y $PKGNAME"
            else
                "$APT" install -y "$PKGNAME"
            fi
        fi
    done
}

# Update the package database
if is_root
then
    $APT update
fi

# Essential packages
pkg acl
pkg attr
pkg auditd
pkg bash-completion
pkg bc
pkg binutils
pkg busybox-static
pkg ca-certificates
pkg ccze
pkg colordiff
pkg diffstat
pkg dos2unix
pkg file
pkg fortune-mod
pkg fortunes
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
pkg procps
pkg progress
pkg psmisc
pkg pv
pkg ripgrep
pkg rlwrap
pkg screen
pkg strace
pkg sudo
pkg time
pkg tmux
pkg zsh

# Hardware and TTY
pkg acpica-tools
pkg console-data
pkg crda
pkg fwupd
pkg gpm
pkg iw
pkg lm-sensors
pkg lshw
pkg pciutils
pkg picocom
pkg rfkill
pkg usbutils
pkg wireless-tools
pkg wpasupplicant

# Archives and filesystems
pkg btrfs-progs
pkg cabextract
pkg cpio
pkg cryfs
pkg cryptsetup
pkg dosfstools
pkg eject
pkg exfat-utils
pkg extundelete
pkg innoextract
pkg lvm2
pkg lzop
pkg mdadm
pkg mtd-utils
pkg mtools
pkg ntfs-3g
pkg p7zip-full
pkg squashfs-tools
pkg unzip
pkg zip

# p7zip-rar is in non-free
if is_available p7zip-rar
then
    pkg p7zip-rar
fi

# Network
pkg arping
pkg arptables
pkg bridge-utils
pkg curl
pkg dnsmasq-base
pkg dnsutils
pkg ebtables
pkg fail2ban
pkg ftp
pkg hping3
pkg iftop
pkg iptables-persistent
pkg ldap-utils
pkg ldnsutils
pkg lftp
pkg links
pkg mariadb-client
pkg mutt
pkg ndisc6
pkg net-tools
pkg netcat
pkg nftables
pkg nmap
pkg rsync
pkg smbclient
pkg snmp
pkg socat
pkg sqlmap
pkg ssh
pkg sshfs
pkg tcpdump
pkg telnet
#tor tor-geoipdb torsocks
pkg tshark
pkg ulogd2
pkg unbound
pkg wget
pkg whois

# Development
pkg build-essential
pkg cargo
pkg clang
pkg cmake
pkg fakeroot
pkg gdb
pkg git
pkg highlight
pkg ipython
pkg libcap-ng-utils
pkg ltrace
pkg nodejs
#pkg php
pkg pkg-config
pkg pypy
pkg python
pkg python-dev
pkg python-setuptools
pkg python-virtualenv
pkg python3
pkg python3-dev
pkg python3-venv
pkg python3-setuptools
pkg rake
pkg ruby
pkg rust
pkg shellcheck

# Other
pkg cmatrix
pkg figlet
pkg john
pkg lolcat
pkg sl

# Debian-specific packages
if is_available apt-listbugs
then
    # apt-listbugs is not available on Ubuntu
    pkg apt-listbugs
fi
pkg apt-listchanges
pkg apt-transport-https
pkg apt-utils
pkg debian-keyring
pkg debsums

if "$INSTALL_DESKTOP"
then
    # X11 server
    pkg rxvt-unicode
    pkg wmctrl
    pkg x11-utils
    pkg xinput
    pkg xorg
    pkg xscreensaver
    pkg xsel
    pkg xserver-xorg
    pkg xterm

    # Fonts
    pkg fonts-droid-fallback
    pkg fonts-freefont-ttf
    pkg fonts-inconsolata
    pkg fonts-liberation
    pkg fonts-vlgothic
    pkg ttf-bitstream-vera
    pkg ttf-dejavu

    # Sound
    pkg alsa-utils
    pkg audacity
    pkg paprefs
    pkg pavucontrol
    pkg pulseaudio
    pkg pulseaudio-utils

    # Applications
    pkg arandr
    pkg baobab
    pkg bleachbit
    pkg eog
    pkg evince
    pkg firejail
    pkg ffmpeg
    pkg file-roller
    pkg filezilla
    pkg gedit
    pkg gedit-plugins
    pkg gimp
    pkg gitk
    pkg gnome-system-monitor
    pkg gparted
    pkg graphviz
    pkg gvfs
    pkg kismet
    pkg meld
    pkg modemmanager
    pkg mupdf
    pkg network-manager-gnome
    pkg network-manager
    pkg pandoc
    pkg parted
    pkg pdf-presenter-console
    pkg qpdf
    #pkg texlive-full
    pkg tk
    pkg vlc
    pkg vlc-plugin-notify
    pkg wireshark-gtk
    pkg xdg-utils
    pkg xsensors
    pkg xterm

    # Ubuntu uses chromium-browser and Debian used chromium
    if is_available chromium-browser
    then
        pkg chromium-browser
    else
        pkg chromium
    fi

    # Debian uses firefox-esr
    if is_available firefox-esr
    then
        pkg firefox-esr
    else
        pkg firefox
    fi

    # Use keepass2 where available (Ubuntu)
    if is_available keepass2
    then
        pkg keepass2
    else
        pkg keepass
    fi

    # Ubuntu does not have libreoffice-fresh
    if is_available libreoffice-fresh
    then
        pkg libreoffice-fresh
    else
        pkg libreoffice
    fi

    # Language
    pkg hunspell-en-gb
    pkg hunspell-en-us
    pkg hunspell-fr
    pkg mythes-en-us
    pkg mythes-fr

    # Libraries
    pkg libgtk-3-dev
    pkg libsdl2-dev
fi

if "$INSTALL_GDM"
then
    pkg gdm3
fi

if "$INSTALL_LIGHTDM"
then
    pkg gnome-themes-standard
    pkg gtk2-engines
    pkg lightdm
    pkg lightdm-gtk-greeter
fi

if "$INSTALL_XFCE"
then
    pkg desktop-base
    pkg libxfce4util-bin
    pkg menu
    pkg notification-daemon
    pkg tango-icon-theme
    pkg thunar-archive-plugin
    pkg thunar-media-tags-plugin
    pkg thunar-volman
    pkg tumbler
    pkg upower
    pkg xdg-user-dirs
    pkg xfce4
    pkg xfce4-goodies
    pkg xfce4-notifyd
    pkg xfce4-power-manager
    pkg xfce4-volumed
    pkg xfwm4-themes

    if "$INSTALL_GDM"
    then
        # https://goodies.xfce.org/projects/panel-plugins/xfswitch-plugin
        # "At the moment it relies on GDM, but other display managers will be supported in the future."
        pkg xfswitch-plugin
    fi
fi
