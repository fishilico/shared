Master Boot Record
==================

The MBR (Master Boot Record) is the first sector of a hard disk drive.
Historically this sector is 512-bytes wide and contains code loaded from the
BIOS and the DOS partition table (up to 4 primary partitions). Nowadays there
exist other ways of booting (like UEFI) and of formatting the partition table
(like GPT).


Binary structure
----------------

The MBR size is always 512 bytes. Its legacy structure is:

+---------------+--------------+---------------------------+
|    Address    | Size (bytes) | Description               |
+===============+==============+===========================+
| ``000`` (  0) |          446 | Bootstrap code area       |
+---------------+--------------+---------------------------+
| ``1BE`` (446) |           16 | Partition entry #1        |
+---------------+--------------+---------------------------+
| ``1CE`` (462) |           16 | Partition entry #2        |
+---------------+--------------+---------------------------+
| ``1DE`` (478) |           16 | Partition entry #3        |
+---------------+--------------+---------------------------+
| ``1EE`` (494) |           16 | Partition entry #4        |
+---------------+--------------+---------------------------+
| ``1FE`` (510) |            2 | Signature (``0x55 0xAA``) |
+---------------+--------------+---------------------------+

A partition entry has this structure:

+-------+----------------+----------------+----------------+----------------+
|       |     ``0``      |     ``1``      |     ``2``      |     ``3``      |
+=======+================+================+================+================+
| ``0`` |      Flag      |           CHS address of first sector            |
+-------+----------------+--------------------------------------------------+
| ``4`` |      Type      |            CHS address of last sector            |
+-------+----------------+--------------------------------------------------+
| ``8`` |           LBA (Logical Block Address) of the partition            |
+-------+-------------------------------------------------------------------+
| ``C`` |                         Number of sectors                         |
+-------+-------------------------------------------------------------------+

* Flag: bit 7 define the *active* state (ie. bootable) of the partition.
* CHS addresses (Cylinder, Head, Sector) are stored in 3 bytes, h7-0, c9-8 s5-0
  and c7-0:

  * c9-0 is the track number, from 0 to 1023
  * h7-0 is the head number, from 0 to 254
  * s5-0 is the sector number, from 1 to 63

* LBA and number of sectors are both written in Little Endian.
* If a sector is 512-bytes wide, the maximum size of a partition is 2TB.
* Partition types includes:

  * ``0x05`` for extended,
  * ``0x07`` for NTFS,
  * ``0x0c`` for FAT 32 with LBA,
  * ``0x17`` for hidden NTFS,
  * ``0x83`` for Linux (ext2/ext3/ext4),
  * ``0x8e`` for LVM

The mapping between CHS and LBA depends on the disk geometry (number of heads
per cylinder and number of sectors per track):

    LBA = ((C * HPC) + H) * SPT + (S - 1)

Maximum values are SPT = 63 and HPC = 255. With these values, a partition which
starts at LBA 2048 has CHS address (0, 32, 33), which is encoded ``20 21 00``.
When the LBA is too large, the CHS address will be (1023, 254, 63), which is
encoded ``fe ff ff``.


Bootstrap code
--------------

The MBR bootstrap code is loaded by the BIOS in real mode (16-bits operations
and addressing mode) at adress ``0000:7C00`` (which is also ``07C0:0000``).

Here are some useful BIOS interrupts:

* Interrupt ``0x10``, video:

  * ``AH = 0x00``: set video mode ``AL``.

    * ``AL = 0x01``: text resolution 40x25, pixel resolution 640x400, 16 colors, 8 pages.
    * ``AL = 0x03``: text resolution 80x25, pixel resolution 720x400, 16 colors, 8 pages.
    * ``AL = 0x12``: text resolution 80x30, pixel resolution 640x480, colors 16/256K, VGA.

  * ``AH = 0x02``: set cursor position of page ``BH`` to ``DX``.

    * ``DH`` = row.
    * ``DL`` = column.

  * ``AH = 0x03``: read cursor position of page ``BH`` in ``DX``.

  * ``AH = 0x05``: set active display page to page number ``AL``.

  * ``AH = 0x06``: scroll up window by ``AL`` lines (0 clears the entire window).

    * ``BH`` = colors used to write blank lines at top of window (``0x42`` means background color red, foreground color green)
    * ``CH``, ``CL`` = row, column of window's upper left corner
    * ``DH``, ``DL`` = row, column of window's lower right corner

  * ``AH = 0x07``: scroll down window by ``AL`` lines (0 clears the entire window). Same parameters as ``AH = 0x06``.

  * ``AH = 0x0B``: set background color ``BX`` (depending on video mode).

  * ``AH = 0x0E``: print ASCII character in ``AL``, in teletype mode.

    * ``BH`` = page number, ``BL`` = foreground pixel color:

      * ``BL = 0x00`` = black.
      * ``BL = 0x01`` = blue.
      * ``BL = 0x02`` = green.
      * ``BL = 0x03`` = cyan.
      * ``BL = 0x04`` = red.
      * ``BL = 0x05`` = magenta.
      * ``BL = 0x06`` = brown.
      * ``BL = 0x07`` = ligth gray.
      * ``BL = 0x08`` = dark gray.
      * ``BL = 0x09`` = light blue.
      * ``BL = 0x0A`` = ligth green.
      * ``BL = 0x0B`` = ligth cyan.
      * ``BL = 0x0C`` = ligth red.
      * ``BL = 0x0D`` = ligth magenta.
      * ``BL = 0x0E`` = yellow.
      * ``BL = 0x0F`` = white.

    * Newline are done with CRLF (``\n\r = 0x0A 0x0D``).
    * Bell (BEL) is ``0x07`` and backspace (BS) is ``0x08``.

  * ``AH = 0x13``: write ``CX`` characters from ``BP``.

    * ``AL = 1`` to update the cursor after writing and use ``BL`` attribute (color).
    * ``AL = 2`` to use a string alternating characters and attributes.
    * ``AL = 3`` to update the cursor and use an alternated string.
    * ``BH`` = page number, ``BL`` = foreground pixel color.
    * ``DX`` = cursor position.

* Interrupt ``0x13``, disk I/O. On return, most commands clear ``CF`` on success
  and set it on error, with ``AH`` being a status code. Drive numbers begins
  with ``0x00`` for floppies and ``0x80`` for hard disks.

  * ``AH = 0x00``: reset disk number ``DL``. and return status in ``CF, AH``.

  * ``AH = 0x01``: get disk status in ``AL``.

  * ``AH = 0x02``: read disk sectors. Parameters:

    * ``AL`` = number of sectors to read
    * ``DH, CL, CH`` = CHS address, in format ``h7-0, c9-8 s5-0, c7-0``
    * ``DL`` = drive number (``0x80`` for first drive)
    * ``ES:BX`` = pointer to buffer
    * Returns status in ``CF, AH`` and number of sectors read in ``AL``

  * ``AH = 0x03``: write disk sectors. Same parameters as for ``AH = 0x02``.

  * ``AH = 0x08``: get drive parameters of drive number ``DL``. Returns:

    * ``CF, AH`` = error/status
    * ``CH`` = low order byte of cylinder count (c7-0)
    * ``CL`` = sectors per track (6 bits) and bits c9-8 of cylinder count
    * ``DH`` = number of heads
    * ``DL`` = number of drives attached
    * ``ES:DI`` = ?

* Interrupt ``0x16``, keyboard services:

  * ``AH = 0x00``: read a character from keyboard (wait key). Returns:

    * ``AH`` = BIOS scan code
    * ``AL`` = ASCII character

  * ``AH = 0x01``: check for keyboard buffer. Returns:

    * ``ZF`` = 0 is a keystroke is available, 1 otherwise
    * ``AH`` = BIOS scan code
    * ``AL`` = ASCII character

  * ``AH = 0x02``: read keyboard shift status

* Interrupt ``0x18``, Boot Fault Routine.

* Interrupt ``0x19``, system reboot.

* Interrupt ``0x1A``, Real Time Clock (RTC) services:

  * ``AH = 0x00``: read RTC (get system time)

    * ``AL``: midnight counter
    * ``CX:DX``: number of clock ticks since midnight

  * ``AH = 0x01``: set RTC
  * ``AH = 0x02``: read RTC time
  * ``AH = 0x03``: set RTC time
  * ``AH = 0x04``: read RTC date
  * ``AH = 0x05``: set RTC date


Tips
----

To extract the MBR from ``/dev/sda`` with ``dd`` you may do::

    dd bs=512 count=1 if=/dev/sda of=mbr.bin

To flash the bootstrap code of a MBR without overwritting the partition table::

    dd bs=440 count=1 conv=notrunc if=mbr.bin of=/dev/sda

To disassemble a boot record with ``objdump``, you may do::

    objdump -D -b binary -mi386 -Maddr16,data16 path/to/mbr

Some websites:

* Syslinux MBR implementation: http://git.kernel.org/cgit/boot/syslinux/syslinux.git/tree/mbr
* GRUB boot record: http://git.savannah.gnu.org/cgit/grub.git/tree/grub-core/boot/i386/pc/diskboot.S
* Wikipedia MBR article: http://en.wikipedia.org/wiki/Master_boot_record
* Wikipedia BIOS interrupts: http://en.wikipedia.org/wiki/BIOS_interrupt_call
  https://en.wikipedia.org/wiki/INT_10H
* BIOS article os OSDev wiki: http://wiki.osdev.org/BIOS
* Interrupt Jump Table: http://www.ctyme.com/intr/int.htm
* Linux boot sector for x86: https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/boot/header.S
* QEmu seabios source: http://git.qemu.org/?p=seabios.git;a=tree
