Using Proxmark3 to play with RFID and NFC
=========================================

Introduction
------------

* RFID: Radio-Frequency Identification (usually only identification for access control)
* NFC: Near-Field Communication, like RFID.
  Data rates from 106 kbits/s to 424 kbits/s.
  Range is about 4cm.

Frequencies:

* LF (Low Frequency): 125 KHz and 134 KHz.
  The state of the circuit survives electrical cut.
  This is used in animals tracking chips, vehicle immobilizers in car keys, access control, etc.
  The antenna has ~100 loops.
* HF (High Frequency): 13.56 MHz. The antenna has 3-7 loops. Standards/norms:

  * FeliCa
  * ISO/IEC 14443A : MiFare, DesFire, EMV payment, etc. (can be emulated by smartphones)
  * ISO/IEC 14443B : Navigo passes
  * ISO/IEC 15693 : "vicinity cards", for greater distance (1-1.5m). For example: skidata on ski passes

* UHF (Ultra High Frequency): 860-930 MHz (clothes in shops, logistics, etc.). The antenna is a symmetric dipole.
* Microwave: 2.4 GHz (active tags)

The ELECHOUSE Proxmark III device targets LF and HF systems.

NFC types:

* type 1 : ISO/IEC 18092
* type 2 : ISO/IEC 21481

On a NFC tag:

* UID
* memory with pages (read/lock with OTP = one-time programmable bit, fuses)
* filesystem (like DesFire)
* Smart Cards: ISO 7816-4 over NFC


Documentation
-------------

* https://github.com/RfidResearchGroup/proxmark3/ RRG/Iceman repo - Proxmark3/Proxmark/RFID/NFC

  * https://github.com/Proxmark/proxmark3 (official from Piwi, with a wiki)
  * https://github.com/iceman1001/proxmark3 (fork, deprecated since 2019)

* http://nfc-tools.org/
* http://wiki.yobi.be/ Philippe Teuwen's (doegox) wiki
* http://proxmark.org/forum/index.php Proxmark3 developers community

* https://cdn.shopify.com/s/files/1/0847/7088/files/Proxmark3_V2_User_Guid.pdf
  Elechouse PROXMARK 3 User Guide
* https://cdn.shopify.com/s/files/1/0847/7088/files/Assemble_Instruction.pdf
  Elechouse PROXMARK 3 Assemble instructions
* https://legacysecuritygroup.com/index.php/categories/9-rfid/7-proxmark-3-emulating-hid-tags-in-standalone-mode
  Firmware/Instructions for Proxmark3 Standalone Emulation/Cloning/Brute-Forcing of RFID tags with the Elechouse RDV2 or the Original Proxmark3

Smartphone applications:

* NFC TagInfo by NXP (https://play.google.com/store/apps/details?id=com.nxp.taginfolite)
* NFC TagWriter by NXP (https://play.google.com/store/apps/details?id=com.nxp.nfc.tagwriter)
* MIFARE Classic Tool (MCT) (https://play.google.com/store/apps/details?id=de.syss.MifareClassicTool)
  can be used to dump MIFARE Classic access control cards
* MIFARE DESFire EV1 NFC Tool (https://play.google.com/store/apps/details?id=com.skjolberg.mifare.desfiretool)

The main board of the Proxmark III V2 consists in:

* CPU : ARM, 512K (AT91SAM7S512) of flash memory, 64kB of RAM
* FPGA : Xilinx Spartan-II
* Two independent RF circuits, HF and LF, antennas using MMCX (micro-miniature coaxial) sockets
* Power : through USB port or battery
* Connectivity : Micro-USB port for PC and MMCX sockets for antennas
* User interface: one button, one switch, 6 LEDs.

Several kinds of RFID tag exists to perform proof of concepts:

* EM4XX ID tag: LF, Fixed ID
* T5577 card: LF, Modify ID (used to clone another tag)
* HID Prox II: LF, read/write user data
* MIFARE S50 (M1): HF, Fixed UID, read/write user data
* MIFARE Ultralight (M0): HF, Fixed UID, read/write user data
* MIFARE UID (Chinese Magic Card): HF, Modify UID, used to clone, read/write user data


Flashing the Proxmark
---------------------

* Configure the platform in ``proxmark3/Makefile.platform.sample``::

      PLATFORM=PM3OTHER

* On Proxmark3 RDV4 with Bluetooth: ``PLATFORM_EXTRAS=BTADDON``
* Upgrade the firmware::

      pm3_flash_fullimage

* Upgrade the firmware and the bootloader::

      proxmark3 /dev/ttyACM0 --flash --unlock-bootloader --image bootrom/obj/bootrom.elf
      proxmark3 /dev/ttyACM0 --flash --image armsrc/obj/fullimage.elf

Using ``pm3``:

* Custom scripts in ``~/proxmark3/cmdscripts/``, listed with ``script list``
* Test cards::

      # Low Frequency antenna (stop by pressing Enter or the PM button)
      lf tune

      # High Frequency antenna
      hf tune

      # Measure antenna characteristics
      hw tune

      # ... result:
      [=] Measuring antenna characteristics, please wait...

      [=] You can cancel this operation by pressing the pm3 button
      ..

      [+] LF antenna: 44.75 V - 125.00 kHz
      [+] LF antenna: 19.69 V - 134.83 kHz
      [+] LF optimal: 44.75 V - 125.00 kHz
      [+] LF antenna is OK

      [+] HF antenna: 29.50 V - 13.56 MHz
      [+] HF antenna is OK

      [+] Displaying LF tuning graph. Divisor 88 is 134.83 kHz, 95 is 125.00 kHz.

* Identify the type of a tag::

      # Use a bunch of commands
      auto

      # High frequency
      hf search

      # Example with a "magic" chinese card
      [=] Checking for known tags...

      [-] Searching for ISO14443-A tag... UID : 80 93 96 02
      ATQA : 00 04
       SAK : 08 [2]
      TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1 | 1k Ev1
      [=] proprietary non iso14443-4 card found, RATS not supported
      [+] Magic capabilities : Gen 1a
      [+] Prng detection: WEAK

      [+] Valid ISO14443-A tag  found

      # Same with Low Frequency (there are many possible algorithms)
      lf search
      [=] NOTE: some demods output possible binary
      [=] if it finds something that looks like a tag
      [=] False Positives ARE possible
      [=]
      [=] Checking for known tags...
      [=]
      [+] EM410x pattern found

      EM TAG ID      : 001241C672

      Possible de-scramble patterns

      Unique TAG ID  : 004882634E
      HoneyWell IdentKey {
      DEZ 8          : 04310642
      DEZ 10         : 0306300530
      DEZ 5.5        : 04673.50802
      DEZ 3.5A       : 000.50802
      DEZ 3.5B       : 018.50802
      DEZ 3.5C       : 065.50802
      DEZ 14/IK2     : 00000306300530
      DEZ 15/IK3     : 000001216504654
      DEZ 20/ZK      : 00000408080206030414
      }
      Other          : 50802_065_04310642
      Pattern Paxton : 5637234 [0x560472]
      Pattern 1      : 8563116 [0x82A9AC]
      Pattern Sebury : 50802 65 4310642  [0xC672 0x41 0x41C672]

      [+] Valid EM410x ID found!

      [+] Chipset detection: T55xx
      [=] Hint: try `lf t55xx` commands

      # To read a LF tag
      lf read
      data plot

      # If "Valid EM410x ID found", there are "lf em" commands
      # Read the content of the card
      lf em 410x_read

      # To clone a tag with T55xx (like a T5577 card), there are "lf t55xx" commands
      # This kind of LF card emits data in cycles
      lf t55xx config
      lf t55xx detect
      lf t55xx dump

      # Read MIFARE Classic tags like a reader:
      hf 14a reader

      # Snooping MIFARE between a tag and a reader
      hf 14a snoop
      hf list 14a

      # For HF MIFARE Classic tags, there are attacks:
      # * old attack: DarkSide/Courtois/...
      # * nested attack
      # * new cards: hard-nested attack
      #
      # Default keys: https://github.com/RfidResearchGroup/proxmark3/blob/3d366d50ef225fff6e5dc61f0decf718b2a0a5f7/client/mifare/mifaredefault.h#L16
      hf mf autopwn

      # Check a key A against every sector and save it, if found, in
      # hf-mf-AABBCCDD-key.bin where AABBCCDD is the UID of the card
      hf mf chk *1 A 1234567890ab d

NFC MIFARE Classic
------------------

MIFARE Classic is a technology from NXP Semiconductors since 1994 that is used in many contactless smart cards for access control.
It uses parts 1-3 of ISO/IEC 14443 Type A 13.56 MHz contactless smart card and an NXP proprietary security protocol for authentication and ciphering.
It provides 1024 bytes of data storage, split into 16 sectors.

Each sector contains 64 bytes:

* 48 bytes of data in 3 blocks of 16 bytes
* 6 bytes for "key A" (48-bit key)
* 4 bytes for access control flags (ACs)
* 6 bytes for "key B" (48-bit key)

The first 16 bytes of sector 0 contain the UID (4 bytes) and manufacturing information (12 bytes) of the card.

The access control flags define what is allowed for each block of 16 bytes.
They consist in with 3 bits for each of the 4 blocks: C1, C2, C3.

With Ci_j being the access control bit Ci for block j (block 3 being the one with keys) and !Ci_j its opposite, the bytes of ACs are:

+-------------------+-------+-------+-------+-------+-------+-------+-------+-------+
| byte 6 of block 3 | !C2_3 | !C2_2 | !C2_1 | !C2_0 | !C1_3 | !C1_2 | !C1_1 | !C1_0 |
+-------------------+-------+-------+-------+-------+-------+-------+-------+-------+
| byte 7 of block 3 |  C1_3 |  C1_2 |  C1_1 |  C1_0 | !C3_3 | !C3_2 | !C3_1 | !C3_0 |
+-------------------+-------+-------+-------+-------+-------+-------+-------+-------+
| byte 8 of block 3 |  C3_3 |  C3_2 |  C3_1 |  C3_0 |  C2_3 |  C2_2 |  C2_1 |  C2_0 |
+-------------------+-------+-------+-------+-------+-------+-------+-------+-------+
| byte 9 of block 3 | User Data                                                     |
+-------------------+-------+-------+-------+-------+-------+-------+-------+-------+

For data blocks, the meaning of the 3 access control bits are:

+----+----+----+---------+---------+-----------+----------------+-------------+
| C1 | C2 | C3 | Read    | Write   | Increment | Dec/Trans/rest | Application |
+====+====+====+=========+=========+===========+================+=============+
| 0  | 0  | 0  | key A|B | key A|B | key A|B   | key A|B        | Transport   |
+----+----+----+---------+---------+-----------+----------------+-------------+
| 0  | 1  | 0  | key A|B | never   | never     | never          | R/W block   |
+----+----+----+---------+---------+-----------+----------------+-------------+
| 1  | 0  | 0  | key A|B | key B   | never     | never          | R/W block   |
+----+----+----+---------+---------+-----------+----------------+-------------+
| 1  | 1  | 0  | key A|B | key B   | key B     | Key A|B        | value block |
+----+----+----+---------+---------+-----------+----------------+-------------+
| 0  | 0  | 1  | key A|B | never   | never     | Key A|B        | value block |
+----+----+----+---------+---------+-----------+----------------+-------------+
| 0  | 1  | 1  | key B   | key B   | never     | never          | R/W block   |
+----+----+----+---------+---------+-----------+----------------+-------------+
| 1  | 0  | 1  | key B   | never   | never     | never          | R/W block   |
+----+----+----+---------+---------+-----------+----------------+-------------+
| 1  | 1  | 1  | never   | never   | never     | never          | R/W block   |
+----+----+----+---------+---------+-----------+----------------+-------------+

For the last block, the meaning of the 3 access control bits are:

+----+----+----+---------+----------+---------+----------+---------+----------+
| C1 | C2 | C3 | Read KA | Write KA | Read AC | Write AC | Read KB | Write KB |
+====+====+====+=========+==========+=========+==========+=========+==========+
| 0  | 0  | 0  | never   | key A    | key A   | never    | key A   | key A    |
+----+----+----+---------+----------+---------+----------+---------+----------+
| 0  | 1  | 0  | never   | never    | key A   | never    | key A   | never    |
+----+----+----+---------+----------+---------+----------+---------+----------+
| 1  | 0  | 0  | never   | key B    | key A|B | never    | never   | key B    |
+----+----+----+---------+----------+---------+----------+---------+----------+
| 1  | 1  | 0  | never   | never    | key A|B | never    | never   | never    |
+----+----+----+---------+----------+---------+----------+---------+----------+
| 0  | 0  | 1  | never   | key A    | key A   | Key A    | key A   | key A    |
+----+----+----+---------+----------+---------+----------+---------+----------+
| 0  | 1  | 1  | never   | key B    | key A|B | Key B    | never   | key B    |
+----+----+----+---------+----------+---------+----------+---------+----------+
| 1  | 0  | 1  | never   | never    | key A|B | Key B    | never   | never    |
+----+----+----+---------+----------+---------+----------+---------+----------+
| 1  | 1  | 1  | never   | never    | key A|B | never    | never   | never    |
+----+----+----+---------+----------+---------+----------+---------+----------+

* ``AC = FF078069`` (default) means: Key A has full access, key B can R/W all data blocks

  - block 0: C1C2C3 = 000 (keys A and B can read, write, increment and decrement all blocks)
  - block 1: C1C2C3 = 000
  - block 2: C1C2C3 = 000
  - block 3: C1C2C3 = 001 (key A can read everything but key A)
  - user data: 69

* ``AC = 787788xx`` (A for read, B for admin) means: Key A can read blocks and ACs, Key B can R/W blocks and ACs, Key B can write Keys A and B

  - block 0: C1C2C3 = 100 (key A can read, key B can read and write)
  - block 1: C1C2C3 = 100
  - block 2: C1C2C3 = 100
  - block 3: C1C2C3 = 011 (key A can read ACs, key B can read ACs and write keys and ACs)
