Initial flash of the Arduino Uno
================================

Some Arduino Uno comes preloaded with a program called Firmata.  Arduino SDK
provides its source code under LGPL v2.1 license so it is legally possible to
redistribute the binary form of Firmata which has been found on an Arduino.

Some links:

* http://www.firmata.org/wiki/Main_Page
* https://github.com/arduino/Arduino/tree/master/libraries/Firmata
* https://github.com/arduino/Arduino/blob/master/hardware/arduino/boards.txt


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

The IHEX format can be converted to an usual binary file with ``avr-objcopy``::

    avr-objcopy -I ihex -O binary flash.hex flash.bin
