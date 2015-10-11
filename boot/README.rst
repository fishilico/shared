Boot-related stuff
==================

This directory contains files related to the boot process of a system:

* ``efi/`` directory contains programs which can be built for a UEFI (Unified
  Extensible Firmware Interface) platform, as well as a script to boot these
  programs from QEmu using Tianocore UEFI firmware (OVMF)
* ``mbr/`` directory contains code and documentation about the MBR (Master Boot
  Record) of disks and 16-bit x86 BIOS interrupts.

Related web links
-----------------

General information about operating system internals:

* http://littleosbook.github.io/
  The little book about OS development
* http://0xax.gitbooks.io/linux-insides/content/index.html
  linux-internals - A series of posts about the linux kernel
* http://lxr.linux.no/linux-old+v1.0/
  Linux 1.0 source
* http://www.tldp.org/HOWTO/Linux-i386-Boot-Code-HOWTO/index.html
  Linux i386 Boot Code HOWTO

Implementation of x86 BIOS bootloaders which get in 64-bit mode:

* https://github.com/ReturnInfinity/Pure64
  Pure64 - The BareMetal OS kernel loader
* https://github.com/IanSeyler/rustboot64
  A tiny 64 bit kernel written in Rust
