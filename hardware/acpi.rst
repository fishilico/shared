Advanced Configuration and Power Interface
==========================================

On http://www.acpi.info/ ACPI (Advanced Configuration and Power Interface) is defined as establishing *industry-standard interfaces enabling OS-directed configuration, power management, and thermal management of mobile, desktop, and server platforms*.


Short introduction to ACPI interface
------------------------------------

ACPI uses several System Description Tables (SDTs) to present a description of the hardware to the operating system.
Some of these tables contain pseudo-code written in ACPI Machine Language (AML).
The SDTs describe where to find ACPI Registers in the memory.
The Operating System and/or the BIOS (Basic Input/Output System) can them implement drivers for these registers in order to use them.


ACPI tables
-----------

To show the content of ACPI tables, it is possible to use ``acpidump`` from ACPICA project.
In a Qemu virtual machine the output is quite short::

    # acpidump -s
    ACPI: RSDP 0x00000000000F62D0 000014 (v00 BOCHS )
    ACPI: RSDT 0x00000000BFFE178C 000034 (v01 BOCHS  BXPCRSDT 00000001 BXPC 00000001)
    ACPI: DSDT 0x00000000BFFE0040 000B9A (v01 BOCHS  BXPCDSDT 00000001 BXPC 00000001)
    ACPI: FACS 0x00000000BFFE0000 000040
    ACPI: FACP 0x00000000BFFE0BDA 000074 (v01 BOCHS  BXPCFACP 00000001 BXPC 00000001)
    ACPI: SSDT 0x00000000BFFE0C4E 000A76 (v01 BOCHS  BXPCSSDT 00000001 BXPC 00000001)
    ACPI: APIC 0x00000000BFFE16C4 000090 (v01 BOCHS  BXPCAPIC 00000001 BXPC 00000001)
    ACPI: HPET 0x00000000BFFE1754 000038 (v01 BOCHS  BXPCHPET 00000001 BXPC 00000001)

On a real system it is slightly bigger::

    # acpidump -s
    ACPI: RSDP 0x00000000DB960000 000024 (v02 ALASKA)
    ACPI: RSDT 0x00000000DB960028 000058 (v01 ALASKA A M I    01072009 MSFT 00010013)
    ACPI: XSDT 0x00000000DB960088 00008C (v01 ALASKA A M I    01072009 AMI  00010013)
    ACPI: DSDT 0x00000000DB9601A8 00CA40 (v02 ALASKA A M I    00000024 INTL 20091112)
    ACPI: FACS 0x00000000DB99C080 000040
    ACPI: FACP 0x00000000DB96CBE8 00010C (v05 ALASKA A M I    01072009 AMI  00010013)
    ACPI: APIC 0x00000000DB96CCF8 000092 (v03 ALASKA A M I    01072009 AMI  00010013)
    ACPI: FPDT 0x00000000DB96CD90 000044 (v01 ALASKA A M I    01072009 AMI  00010013)
    ACPI: TCPA 0x00000000DB96CDD8 000032 (v02 APTIO4 NAPAASF  00000001 MSFT 01000013)
    ACPI: SSDT 0x00000000DB96CE10 0015C2 (v01 TrmRef PtidDevc 00001000 INTL 20091112)
    ACPI: SSDT 0x00000000DB96E3D8 000539 (v01 PmRef  Cpu0Ist  00003000 INTL 20051117)
    ACPI: SSDT 0x00000000DB96E918 000AD8 (v01 PmRef  CpuPm    00003000 INTL 20051117)
    ACPI: MCFG 0x00000000DB96F3F0 00003C (v01 ALASKA A M I    01072009 MSFT 00000097)
    ACPI: HPET 0x00000000DB96F430 000038 (v01 ALASKA A M I    01072009 AMI. 00000005)
    ACPI: SSDT 0x00000000DB96F468 000315 (v01 SataRe SataTabl 00001000 INTL 20091112)
    ACPI: SSDT 0x00000000DB96F780 001917 (v01 SaSsdt SaSsdt   00003000 INTL 20091112)
    ACPI: DMAR 0x00000000DB971098 0000B8 (v01 INTEL  HSW      00000001 INTL 00000001)
    ACPI: BGRT 0x00000000DB971150 000038 (v00 ALASKA A M I    01072009 AMI  00010013)
    ACPI: SSDT 0x0000000000000000 0003D3 (v01 PmRef  Cpu0Cst  00003001 INTL 20051117)
    ACPI: SSDT 0x0000000000000000 0005AA (v01 PmRef  ApIst    00003000 INTL 20051117)
    ACPI: SSDT 0x0000000000000000 000119 (v01 PmRef  ApCst    00003000 INTL 20051117)

This description of ACPI tables also appears in kernel logs (``dmesg``) when the system boots.

Here is the definition of some acronyms:

* ``APIC``: Advanced Programmable Interrupt Controller
* ``ASF!``: Alert Standard Format
* ``BGRT``: Boot Graphics Resource Table
* ``CPEP``: Corrected Platform Error Polling Table
* ``CSRT``: Core System Resource Table
* ``DBG2``: Debug Port Table 2
* ``DBGP``: Debug Port Table
* ``DMAR``: DMA Remapping Table (which decribres an IOMMU)
* ``DSDT``: Differentiated System Description Table
* ``ECDT``: Embedded Controller Boot Resources Table
* ``EINJ``: Error Injection Table
* ``ERST``: Error Record Serialization Table
* ``FACP``: ``FADT`` pointer
* ``FACS``: Firmware ACPI Control Structure
* ``FADT``: Fixed ACPI Description Table
* ``FIDT``: unknown, maybe related to identification
* ``FPDT``: Firmware Performance Data Table
* ``GTDT``: Generic Timer Description Table
* ``HEST``: Hardware Error Source Table
* ``HPET``: High Precision Event Timer Table
* ``LPIT``: Low Power Idle Table
* ``MADT``: Multiple APIC Description Table
* ``MCFG``: PCI Express memory mapped configuration space base address Description Table
* ``MPST``: Memory Power StateTable
* ``MSCT``: Maximum System Characteristics Table
* ``MSDM``: Microsoft Data Management (containing MS Windows license key for OEM activation)
* ``PMTT``: Platform Memory Topology Table
* ``PSDT``: Persistent System Description
* ``RASF``: ACPI RAS FeatureTable
* ``RSDP``: Root System Description Pointer
* ``RSDT``: Root System Description Table
* ``SBST``: Smart Battery Table
* ``SLIT``: System Locality Information Table
* ``SRAT``: System Resource Affinity Table
* ``SSDT``: Secondary System Description Table
* ``TCPA``: Trusted Computing Platform Alliance Capabilities Table
* ``TPM2``: Trusted Platform Module 2.0 (from Trusted Computing Group (TCG))
* ``UEFI``: Unified Extensible Firmware Interface
* ``WSMT``: Windows SMM Security Mitigations Table
* ``XSDT``: Extended System Description Table

The address of ``RSDP`` can be found in the read-only BIOS memory area between ``0xe0000`` and ``0x100000`` by looking for signature ``"RSD PTR "``::

    # grep 'System ROM' /proc/iomem
    000f0000-000fffff : System ROM

    # dd status=none if=/dev/mem bs=1 count=$((0x100000-0xe0000)) skip=$((0xe0000)) | \
      od -tx1z -Ax | grep -A1 'RSD PTR'
    0162d0 52 53 44 20 50 54 52 20 f2 42 4f 43 48 53 20 00  >RSD PTR .BOCHS .<
    0162e0 8c 17 fe bf 00 00 00 00 00 00 00 00 00 00 00 00  >................<

On systems booted with UEFI, the EFI Configuration Table contains entries for ACPI tables which contain the value of ``RSDP``::

    # cat /sys/firmware/efi/systab
    ACPI20=0xdb960000
    ACPI=0xdb960000
    SMBIOS=0xdbf7f598

    # dd status=none if=/dev/mem bs=1 count=32 skip=$((0xdb960000)) | \
      od -tx1z -Ax |grep -A1 'RSD PTR'
    000000 52 53 44 20 50 54 52 20 99 41 4c 41 53 4b 41 02  >RSD PTR .ALASKA.<
    000010 28 00 96 db 24 00 00 00 88 00 96 db 00 00 00 00  >(...$...........<

    # (echo 'db960000 TOKEN';cat /proc/iomem) | sort | grep -B1 TOKEN |head -n1
    db858000-db99dfff : ACPI Non-volatile Storage


The ``RSDP`` contains an OEM ID, the version of the ACPI specification which is used (0 for ACPI 1.0 and 2 for ACPI 2.0) and physical addresses to ``RSDT`` and ``XSDT`` (for ACPI 2).

All tables begin with a header containing the information which is dumped by ``acpidump -s`` (length, OEM ID string, revision number, etc.).
On Linux, the tables can be read from ``/sys/firmware/acpi/tables``.
For example, to read the ``FADT`` (which is identified by ``FACP``)::

    # xxd /sys/firmware/acpi/tables/FACP
    0000000: 4641 4350 7400 0000 0119 424f 4348 5320  FACPt.....BOCHS 
    0000010: 4258 5043 4641 4350 0100 0000 4258 5043  BXPCFACP....BXPC
    0000020: 0100 0000 0000 febf 4000 febf 0100 0900  ........@.......
    0000030: b200 0000 f1f0 0000 0006 0000 0000 0000  ................
    0000040: 0406 0000 0000 0000 0000 0000 0806 0000  ................
    0000050: e0af 0000 0000 0000 0402 0004 0400 0000  ................
    0000060: ff0f ff0f 0000 0000 0000 0000 0000 0000  ................
    0000070: a580 0000                                ....

This table contains platform-specific parameters to use to operate the system.

``DSDT`` and ``SSDT`` (Differentiated/Secondary System Description Table) contain a system description.
These tables contain AML (ACPI Machine Language) code which can be decompiled using ``iasl``.
For example on a Qemu virtual machine::

    # acpidump -b
    # ls
    apic.dat  dsdt.dat  facp.dat  facs.dat  hpet.dat  rsdp.dat  rsdt.dat  ssdt.dat
    # iasl -e ssdt.dat -d dsdt.dat

    Intel ACPI Component Architecture
    ASL+ Optimizing Compiler version 20141107-64 [Dec  2 2014]
    Copyright (c) 2000 - 2014 Intel Corporation

    Loading Acpi table from file   dsdt.dat - Length 00002970 (000B9A)
    ACPI: DSDT 0x0000000000000000 000B9A (v01 BOCHS  BXPCDSDT 00000001 BXPC 00000001)
    Acpi table [DSDT] successfully installed and loaded
    Loading Acpi table from file   ssdt.dat - Length 00002678 (000A76)
    ACPI: SSDT 0x0000000000000000 000A76 (v01 BOCHS  BXPCSSDT 00000001 BXPC 00000001)
    Acpi table [SSDT] successfully installed and loaded
    Pass 1 parse of [SSDT]
    Pass 2 parse of [SSDT]
    Pass 1 parse of [DSDT]
    Pass 2 parse of [DSDT]
    Parsing Deferred Opcodes (Methods/Buffers/Packages/Regions)

    Parsing completed

    Found 3 external control methods, reparsing with new information
    Pass 1 parse of [DSDT]
    Pass 2 parse of [DSDT]
    Parsing Deferred Opcodes (Methods/Buffers/Packages/Regions)

    Parsing completed
    Disassembly completed
    ASL Output:    dsdt.dsl - 28761 bytes

The generated file, ``dsdt.dsl``, contains ASL (ACPI Source Language) code.
On a Qemu VM the original source file is available on the Internet, with comments:
http://bochs.sourceforge.net/cgi-bin/lxr/source/bios/acpi-dsdt.dsl

Here are some useful predefined items to understand ASL code:

* ``_ADR``: Address property
* ``_CRS``: Current Resource Settings method
* ``_DIS``: Disable Device method
* ``_EJ0``, ``_EJ1``, etc.: Eject Device method
* ``_HID``: Hardware ID property
* ``_MAT``: Multiple APIC Table Entry method
* ``\_SB``: namespace for all device/bus objects
* ``_SRS``: Set Resource Settings method
* ``_STA``: Status method
* ``_PRS``: Possible Resource Settings property
* ``_PRT``: PCI Routing Table (in ``\_SB.PCI0`` scope)
* ``_PTS``: Prepare To Sleep (enter a sleep state, S5 for poweroff)
* ``_UID``: Unique ID property

As ``iasl`` knows all the predefined items (which are enumerated in the specification), it automatically adds a comment in the decompiled code.


How to fetch the boot background image
--------------------------------------

When a computer boots, its BIOS can display a logo (bitmap graphics) which is later accessible to the OS.
This is done using the ``BGRT`` (Boot Graphics Resource Table).

This table may look like this::

    $ xxd /sys/firmware/acpi/tables/BGRT
    00000000: 4247 5254 3800 0000 014d 414c 4153 4b41  BGRT8....MALASKA
    00000010: 4120 4d20 4920 0000 0920 0701 414d 4920  A M I ... ..AMI 
    00000020: 1300 0100 0100 0100 1880 5c83 0000 0000  ..........\.....
    00000030: 6b00 0000 4601 0000                      k...F...

or like this::

    $ xxd /sys/firmware/acpi/tables/BGRT
    00000000: 4247 5254 3800 0000 000e 496e 7465 6c00  BGRT8.....Intel.
    00000010: 4348 4945 4600 0000 0920 0701 414d 4920  CHIEF.... ..AMI 
    00000020: 1300 0100 0100 0000 18e0 2dce 0000 0000  ..........-.....
    00000030: 0000 0000 0000 0000                      ........

This structure is defined in Linux:``include/acpi/actbl1.h``:

.. code-block:: c

                struct acpi_table_bgrt {
                    struct acpi_table_header { /* Common ACPI table header */
    /* 0x0000 */        char signature[ACPI_NAME_SIZE=4]; /* ASCII table signature */
    /* 0x0004 */        u32 length; /* Length of table in bytes, including this header */
    /* 0x0008 */        u8 revision; /* ACPI Specification minor version number */
    /* 0x0009 */        u8 checksum; /* To make sum of entire table == 0 */
    /* 0x000a */        char oem_id[ACPI_OEM_ID_SIZE=6]; /* ASCII OEM identification */
    /* 0x0010 */        char oem_table_id[ACPI_OEM_TABLE_ID_SIZE=8]; /* ASCII OEM table identification */
    /* 0x0018 */        u32 oem_revision; /* OEM revision number */
    /* 0x001c */        char asl_compiler_id[ACPI_NAME_SIZE=4]; /* ASCII ASL compiler vendor ID */
    /* 0x0020 */        u32 asl_compiler_revision; /* ASL compiler version */
                    } header; /* Common ACPI table header, decoded by acpidump -s:
                                    length = 0x38
                                    (v01 ALASKA A M I    01072009 AMI  00010013)
                                    (v00 Intel  CHIEF    01072009 AMI  00010013)
                               */
    /* 0x0024 */    u16 version = 1;
    /* 0x0026 */    u8 status = 1; /* 1 when displayed, 0 when disabled at boot */
    /* 0x0027 */    u8 image_type = 0; /* "bitmap" */
    /* 0x0028 */    u64 image_address = 0x835c8018; /* bitmap physical address */
    /* 0x0030 */    u32 image_offset_x = 0x6b = 107;
    /* 0x0034 */    u32 image_offset_y = 0x146 = 326;
                };


When Linux is compiled with ``CONFIG_ACPI_BGRT``, the ``acpi/bgrt`` driver (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/acpi/bgrt.c) creates entries in the sysfs, documented in https://docs.microsoft.com/en-gb/windows-hardware/drivers/bringup/boot-screen-components:

* ``/sys/firmware/acpi/bgrt/image``: image data of the logo
* ``/sys/firmware/acpi/bgrt/status``: 1 is the logo has been displayed
* ``/sys/firmware/acpi/bgrt/type``: 0 for bitmap
* ``/sys/firmware/acpi/bgrt/version``: always 1
* ``/sys/firmware/acpi/bgrt/xoffset``: X coordinate of the position where to display the image
* ``/sys/firmware/acpi/bgrt/yoffset``: Y coordinate of the position where to display the image

Bitmap images are correctly identified by ``file`` and can be directly opened by usual image viewers::

    $ file /sys/firmware/acpi/bgrt/image
    /sys/firmware/acpi/bgrt/image: PC bitmap, Windows 3.x format, 809 x 116 x 24


Web links
---------

* http://www.acpi.info/ Official website with the latest specification.
* https://www.acpica.org/ ACPI Component Architectures
* https://github.com/acpica/acpica ACPICA code
* https://wiki.archlinux.org/index.php/DSDT Arch Linux wiki article on DSDT
* http://forum.osdev.org/viewtopic.php?t=16990 ACPI poweroff
  (from http://wiki.osdev.org/Shutdown)
* https://docs.microsoft.com/en-us/windows-hardware/drivers/bringup/acpi-system-description-tables
  Microsoft ACPI system description tables
