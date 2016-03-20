Unified Extensible Firmware Interface
=====================================

The UEFI (Unified Extensible Firmware Interface) is a specification which
defines an interface to the platform firmware to access hardware.  On disk,
this specification requires a specific partition table format (e.g. GPT, GUID
Partition Table).  On boot, the system launches executable EFI images written
in PE (Portable Executable) format.  Such an application can use services
provided by the firmware ("Boot Services" and "Runtime Services"), for example
to launch an operating system.


Web links
---------

Linux kernel relevant files:

* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/boot/compressed/head_64.S
  x86_64 EFI stub entrypoint implementation (``efi_pe_entry``)
* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/boot/compressed/eboot.c
  x86 EFI boot file
* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/platform/efi
  x86 EFI platform code
* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/linux/efi.h
  EFI structures and enums

gnu-efi library:

* http://sourceforge.net/p/gnu-efi/code/ci/master/tree/ Git tree
* http://sourceforge.net/p/gnu-efi/code/ci/master/tree/lib/x86_64/efi_stub.S
  x86_64 ABI definition
* http://sourceforge.net/p/gnu-efi/code/ci/master/tree/gnuefi/reloc_x86_64.c
  x86_64 relocations implementation

efitools:

* https://git.kernel.org/cgit/linux/kernel/git/jejb/efitools.git/tree/ Git tree

MSDN:

* http://msdn.microsoft.com/en-us/library/ms235286%28v=vs.120%29.aspx
  Overview of x64 Calling Conventions (UEFI API convention on x86_64)

Other:

* https://github.com/theopolis/uefi-firmware-parser
  UEFI Firmware Parser
