Initial flash of the Arduino Uno
================================

Some Arduino Uno comes preloaded with a program called Firmata.  Arduino SDK
provides its source code under LGPL v2.1 license so it is legally possible to
redistribute the binary form of Firmata which has been found on an Arduino.

Some links:

* http://www.firmata.org/wiki/Main_Page
* https://github.com/arduino/Arduino/blob/master/hardware/arduino/boards.txt
* https://github.com/arduino/Arduino/tree/master/libraries/Firmata
  Firmata firmware included in Arduino project
* https://github.com/firmata/arduino/tree/ccdee5b71779bbc477d3190513c6d46f995c9300
  Firmata 2.2 tree


Dump the flash of an Arduino Uno
--------------------------------

``avrdude`` can dump the content of the flash of an Arduino Uno. The parameters
can be found in ``hardware/arduino/boards.txt`` file from the Arduino SDK::

    uno.name=Arduino Uno
    uno.upload.protocol=arduino
    uno.upload.maximum_size=32256
    uno.upload.speed=115200
    uno.bootloader.low_fuses=0xff
    uno.bootloader.high_fuses=0xde
    uno.bootloader.extended_fuses=0x05
    uno.bootloader.path=optiboot
    uno.bootloader.file=optiboot_atmega328.hex
    uno.bootloader.unlock_bits=0x3F
    uno.bootloader.lock_bits=0x0F
    uno.build.mcu=atmega328p
    uno.build.f_cpu=16000000L
    uno.build.core=arduino
    uno.build.variant=standard

When the Arduino is plugged to an USB port, it can be accessed through
``/dev/ttyACM0`` and thus the ``avrdude`` command to dump is flash is::

    avrdude -c arduino -p atmega328p -P /dev/ttyACM0 -b 115200 -U flash:r:flash.hex:i

This command writes ``flash.hex`` in IHEX format.  This file contains lines
such as::

    :207E0000112484B714BE81FFF0D085E08093810082E08093C00088E18093C10086E08093FC

and ends with::

    :00000001FF

These hexadecimal digits can be split like this:

* ``20``: length in bytes of the data in the line (here 32)
* ``7E00``: 16-bit address where the data lies in the flash memory
* ``00``: the line contains data (this is ``01`` for the last line)
* ``1124...8093``: data, which length has been given beforehand
* ``FC``: checksum of the line, such as the sum of all bytes modulo 256 is zero.

The IHEX format can be converted to an usual binary file with ``objcopy``::

    objcopy -I ihex -O binary flash.hex flash.bin


AVR code
--------

The Arduino processor is an ATmega328p running an 8-bit AVR instruction set.

This instruction-set works on:

* 32 general-purpose 8-bit registers, ``R0``-``R31``
* Some instructions operate on three 16-bit register pairs:

  - ``X``, ``R27:R26`` (``R26`` holds the 8 least significant bits of ``X``),
  - ``Y``, ``R29:R28``,
  - ``Z``, ``R31:R30``.

* The status register ``SREG`` has 8 bits:

  - C, Carry flag
  - Z, Zero flag
  - N, Negative flag
  - V, Overflow flag
  - S, Sign flag
  - H, Half carry
  - T, Bit copy
  - I, Interrupt flag

* There are two 16-bit memory spaces: RAM (Data Space) and Flash (Program
  Memory).
* Indirect memory addressing can be done with ``X``, ``Y``, ``Z``, with
  optionally a post-increment or pre-decrement.
* Instruction opcodes are 2-bytes, and 4-bytes when an immediate data is used.

An IHEX file like ``initialflash.hex`` can be disassembled with::

    avr-objdump -mavr -D -I ihex initialflash.hex

The Common Runtime part of an Arduino program can be disassembled on a build
system with this command::

    avr-objdump -dr  /usr/avr/lib/avr5/crtm328p.o

Documentation:

* http://atmega32-avr.com/Download/atmega328_datasheet.pdf
  8-bit AVR Microcontroller with 4/8/16/32K Bytes In-System Programmable Flash
* http://www.atmel.com/images/doc0856.pdf
  8-bit AVR Instruction Set
* https://en.wikipedia.org/wiki/Atmel_AVR_instruction_set
  Atmel AVR instruction set - Wikipedia
* http://svn.savannah.nongnu.org/viewvc/trunk/avr-libc/include/avr/iom328p.h?root=avr-libc&view=markup
  AVR-libc definition for ATmega328P
