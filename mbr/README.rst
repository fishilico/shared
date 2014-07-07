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

  * ``AH = 0x00``: set video mode ``AL``

  * ``AH = 0x0E``: print ASCII character in ``AL``, in teletype mode.

    * ``BH`` = page number, ``BL`` = foreground pixel color.
    * Newline are done with CRLF (``\n\r = 0x0A 0x0D``).
    * Bell (BEL) is ``0x07`` and backspace (BS) is ``0x08``.

* Interrupt ``0x13`, disk I/O. On return, most commands clear ``CF`` on success
  and set it on error, with ``AH`` being a status code. Drive numbers begins
  with ``0x00`` for floppies and ``0x80`` for hard disks.

  * ``AH = 0x00``: reset disk number ``DL``. and return status in `CF, AH``.

  * ``AH = 0x01``: get disk status in ``AL``.

  * ``AH = 0x02``: read disk sectors. Parameters:

    * ``AL`` = number of sectors to read
    * ``DH, CL, CH`` = CHS address, in format ``h7-0, c9-8 s5-0, c7-0``
    * ``DL`` = drive number (``0x80`` for first drive)
    * ``ES:BX`` = pointer to buffer
    * Returns status in ``CF, AH`` and number of sectors read in ``AL``

  * ``AH = 0x08``: get drive parameters of drive number ``DL``. Returns:

    * ``CF, AH`` = error/status
    * ``CH`` = low order byte of cylinder count (c7-0)
    * ``CL`` = sectors per track (6 bits) and bits c9-8 of cylinder count
    * ``DH`` = number of heads
    * ``DL`` = number of drives attached
    * ``ES:DI`` = ?

* Interrupt ``0x18``, Boot Fault Routine


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
* Wikipedia article: http://en.wikipedia.org/wiki/Master_boot_record
