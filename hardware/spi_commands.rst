SPI commands
============

Some SPI commands found in some hardware:

* Reset: commands ``0x55`` then ``0xAA``

* ``0x01``: ``WRSR``, Write Status Register 1
* ``0x02``: ``WRITE``, Write Data (lower half of memory) ; ``PP``, Page Program (256 bytes max)
* ``0x03``: ``READ``, Read Data (lower half of memory)
* ``0x04``: ``WRDI``, Write Disable (clear ``WEL``)
* ``0x05``: ``RDSR``, Read Status Register 1
* ``0x06``: ``WREN``, Write Enable (set ``WEL``)
* ``0x0a``: Write Data to RAM (upper half of memory)
* ``0x0b``: ``FSTRD``, read data from RAM at 40MHz (upper half of memory)
* ``0x0c``: Burst Read with Wrap ; fast read, 32-bit address
* ``0x11``: Write Status Register 3
* ``0x12``: ``QIEFP``, Quad Input Extended Fast Program
* ``0x15``: Read Status Register 3 ; Read ID (Legacy Command)
* ``0x20``: ``SSE``, SubSector Erase ; Sector Erase (4KB)
* ``0x31``: Write Status Register 2
* ``0x32``: ``QIFP``, Quad Input Fast Program ; Quad Page Program
* ``0x35``: Read Status Register 2
* ``0x36``: Individual Block Lock
* ``0x38``: Enter QPI Mode
* ``0x39``: Individual Block Unlock
* ``0x3b``: ``DOFR``, Dual Output Fast Read ; Fast Read Dual Output
* ``0x3c``: Dual Output Fast Read, 32-bit address
* ``0x3d``: Read Block Lock
* ``0x42``: ``POTP`` Program OTP (One-Time Programmable memory) ; Program Security Register
* ``0x44``: Erase Security Register
* ``0x48``: Read Security Register
* ``0x4b``: ``ROTP``, Read OTP (One-Time Programmable memory) ; Read Unique ID
* ``0x50``: ``EWSR``, enable write status register ; Volatile SR Write Enable ; ``CLFSR``, Clear Flag Status Register
* ``0x52``: Sector Erase (32KB)
* ``0x5a``: Read SFDP Register
* ``0x60``: Chip Erase
* ``0x61``: ``WRVECR``, Write Volatile Enhanced Configuration Register
* ``0x62``: Chip Erase (Legacy Command)
* ``0x65``: ``RDVECR``, Read Volatile Enhanced Configuration Register
* ``0x66``: Enable Reset
* ``0x6b``: ``QOFR``, Quad Output Fast Read ; Fast Read Quad Output
* ``0x6c``: Quad Output Fast Read, 32-bit address
* ``0x70``: ``EBSY``, Enable SO to output RY/BY# status during AAI programming ; ``RFSR``, Read Flag Status Register
* ``0x75``: ``PES``, Program/Erase Suspend ; Erase / Program Suspend
* ``0x77``: Set Burst with Wrap ; Read OTP Security Register
* ``0x79``: Ultra Deep Power-Down
* ``0x7a``: ``PER``, Program/Erase Resume ; Erase / Program Resume
* ``0x7e``: Global Block Lock
* ``0x80``: ``DBSY``, Disable SO as RY/BY# status during AAI programming
* ``0x81``: ``WRVCR``, Write Volatile Configuration Register ; Page Erase
* ``0x85``: ``RDVCR``, Read Volatile Configuration Register
* ``0x90``: Manufacturer/Device ID
* ``0x92``: Mftr./Device ID Dual I/O
* ``0x94``: Mftr./Device ID Quad I/O
* ``0x98``: Global Block Unlock
* ``0x99``: Reset Device
* ``0x9b``: Program OTP Security Register
* ``0x9f``: ``RDID``, Read 9-bytes Device ID ; ``JEDEC ID`` ; Read Manufacturer and Device ID
* ``0xab``: Release Power-Down / ID ; Resume from Deep Power-Down
* ``0xad``: Auto Address Increment Word Program (AAI programming)
* ``0xb1``: ``WRNVCR``, Write NV Configuration Register
* ``0xb5``: ``RDNVCR``, Read NV Configuration Register
* ``0xb9``: ``SLEEP``, Enter Sleep Mode ; Power-Down ; Deep Power-Down
* ``0xbb``: ``DIOFR``, Dual Input/Output Fast Read ; Fast Read Dual I/O
* ``0xc0``: Set Read Parameters
* ``0xc3``: ``SNR``, read 8-byte serial number
* ``0xc7``: ``BE``, Bulk Erase ; Chip Erase
* ``0xd2``: ``DIEFP``, Dual Input Extended Fast Program
* ``0xd8``: ``SE``, Sector Erase ; Block Erase (64KB)
* ``0xe3``: Octal Word Read Quad I/O
* ``0xe5``: ``WRLR``, Write to Lock Register
* ``0xe7``: Word Read Quad I/O
* ``0xe8``: ``RDLR``, Read Lock Register
* ``0xeb``: ``QIOFR``, Quad Input/Output Fast Read ; Fast Read Quad I/O
* ``0xf0``: Reset
* ``0xff``: Exit QPI

Commands from:

* https://www.xilinx.com/support/documentation/application_notes/xapp1233-spi-config-ultrascale.pdf
* http://www.cypress.com/file/46161/download
* http://www.adestotech.com/wp-content/uploads/DS-AT25XE011-059.pdf

Flash device IDs
----------------

Command ``0x9f`` (``RDID``) returns the JEDEC ID of the device.

Some Winbond Serial Flash devices (``ef TT CC``):

* ``TT``: memory type (``40`` for SPI, ``60`` for QPI)
* ``CC``: capacity (``8 << CC`` bits)

* ``ef 40 14`` : W25Q80BL  - 2.5V 8M-BIT SERIAL FLASH MEMORY
* ``ef 40 17`` : W25Q64FV  - 3V 64M-BIT SERIAL FLASH MEMORY
* ``ef 40 18`` : W25Q128FV - 3V 128M-BIT SERIAL FLASH MEMORY, https://www.pjrc.com/teensy/W25Q128FV.pdf

Some Micron devices (fabricant *manufacturer*):

* ``20 ba 17`` : N25Q064A Micron Serial NOR Flash Memory 3V, Multiple I/O, 4KB Sector Erase, https://www.micron.com/~/media/documents/products/data-sheet/nor-flash/serial-nor/n25q/n25q_64a_3v_65nm.pdf
* ``20 bb 17`` : N25Q064A Micron Serial NOR Flash Memory 1.8V, Multiple I/O, 4KB Sector Erase - 64 Mb = 8 MB, https://www.micron.com/~/media/documents/products/data-sheet/nor-flash/serial-nor/n25q/n25q_64mb_1_8v_65nm.pdf
* ``20 ba 18`` : N25Q128 Numonyx 128-Mbit 3 V, multiple I/O, 4-Kbyte subsector erase on boot sectors, XiP enabled, serial flash memory with 108 MHz SPI bus interface, https://www.micron.com/~/media/documents/products/data-sheet/nor-flash/serial-nor/n25q/n25q_128_3_volt_with_boot_sector.pdf
* ``20 bb 18`` : N25Q128A Micron Serial NOR Flash Memory 1.8V, Multiple I/O, 4KB Sector Erase

Some Microchip devices:

* ``bf 25 41`` : SST25VF016B, http://ww1.microchip.com/downloads/en/DeviceDoc/S71271_04.pdf
