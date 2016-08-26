#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Nicolas Iooss
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Decode the initial application on an Arduino Uno, which is Firmata

@author: Nicolas Iooss
@license: MIT
"""
import os.path
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import utils
from atmega328p import ATmega328PMeta, Label


LABELS = [
    Label(0x0068, 'D', 'rodata'),
    Label(0x00c2, 'J', 'constructor_table'),

    # Firmware application code labels
    Label(0x00c8, 'C', 'boot()'),
    Label(0x00d4, 'c', 'Copy .data segment to 0100..01ee'),
    Label(0x00e0, 'C', '_memcpy_data_loop'),
    Label(0x00e4, 'C', '_memcpy_data_loop_start'),
    Label(0x00ea, 'c', 'Clear .bss in 01ee..0378'),
    Label(0x00f2, 'C', '_zeromem_bss_loop'),
    Label(0x00f4, 'C', '_zeromem_bss_loop_start'),
    Label(0x0102, 'C', '_loc_0102'),
    Label(0x010a, 'C', '_loc_010a'),

    Label(0x0118, 'C', 'bad_interrupt'),

    # libc from http://svn.savannah.nongnu.org/viewvc/trunk/avr-libc/?root=avr-libc
    # libc/stdlib/malloc.c
    Label(0x011c, 'C', 'libc.malloc(size=r25:r24)->r25:r24'),

    Label(0x0270, 'C', 'libc.free(p=r25:r24)'),

    # libc/string/strncpy.S
    Label(0x0320, 'C', 'libc.strncpy(dest=r25:r24, src=r23:r22, size=r21:r20)'),

    # libc/string/strrchr.S
    Label(0x033e, 'C', 'libc.strrchr(r25:r24, r22)->r25:r24'),

    # libc/string/strstr.S
    Label(0x0354, 'C', 'libc.strstr(haystack=r25:r24, needle=r23:r22)->r25:r24'),

    # https://github.com/arduino/Arduino/blob/master/libraries/Servo/src/avr/Servo.cpp
    Label(0x0388, 'C', 'Servo::Servo(this=r25:r24)'),
    Label(0x0392, 'c', 'this->servoIndex = ServoCount++'),

    Label(0x03bc, 'C', 'sub_03bc'),

    Label(0x041c, 'C', 'Servo::writeMicroseconds(this=r25:r24, int value=r23:r22)'),

    Label(0x0494, 'C', 'sub_0494'),

    Label(0x04b8, 'C', 'Servo::write(this=r25:r24, int value=r23:r22)'),
    Label(0x04ee, 'c', 'value = map(value, 0, 180, SERVO_MIN(),  SERVO_MAX())...'),

    Label(0x0588, 'C', 'sub_0588'),

    Label(0x0686, 'C', 'sub_0686'),

    # handle_interrupts function
    Label(0x0694, 'C', 'int0b_TIMER1_COMPA_vect'),

    Label(0x080e, 'C', 'FirmataClass::attach(this=r25:r24, byte command=r22, callbackFunction newFunction=r21:r20)'),

    Label(0x084a, 'C', 'FirmataClass::attach(this=r25:r24, byte command=r22, sysexCallbackFunction fct=r21:r20)'),

    Label(0x0852, 'C', 'FirmataClass::systemReset(this=r25:r24)'),

    Label(0x0880, 'C', 'FirmataClass::FirmataClass(this=r25:r24)'),

    Label(0x088a, 'C', 'cons3_initialize_Firmata'),

    Label(0x0894, 'C', 'FirmataClass::pin13strobe(this=r25:r24, int count=r23:r22, ' +
          'int onInterval=r21:r20, int offInterval=r19:r18)'),

    Label(0x0934, 'C', 'FirmataClass::blinkVersion(this=r25:r24)'),

    Label(0x0996, 'C', 'FirmataClass::sendDigitalPort(this=r25:r24, byte portNumber=r22, int portData=r21:r20)'),
    Label(0x09ea, 'C', 'FirmataClass::printVersion(this=r25:r24)'),

    Label(0x0a22, 'C', 'endSysex()'),

    Label(0x0a34, 'C', 'startSysex()'),

    Label(0x0a46, 'C', 'sendValueAsTwo7bitBytes(value=r25:r24)'),

    Label(0x0a8a, 'C', 'FirmataClass::sendSysex(this=r25:r24, byte command=r22, byte bytec=r20, byte* bytev=r19:r18)'),

    Label(0x0adc, 'C', 'FirmataClass::sendString(this=r25:r24, byte command=r22, const char* string=r21:r20)'),
    Label(0x0aec, 'c', 'r20 := strlen(string)'),

    Label(0x0af4, 'C', 'FirmataClass::sendString(this=r25:r24, const char* string=r23:r22)'),

    Label(0x0afe, 'C', 'FirmataClass::sendAnalog(this=r25:r24, byte pin=r22, int value=r21:r20)'),

    Label(0x0b24, 'C', 'FirmataClass::printFirmwareVersion(this=r25:r24)'),

    Label(0x0b92, 'C', 'FirmataClass::processSysexMessage(this=r25:r24)'),

    Label(0x0c20, 'C', 'FirmataClass::processInput(this=r25:r24)'),

    Label(0x0d72, 'C', 'FirmataClass::available(this=r25:r24)->r25:r24'),

    Label(0x0d7c, 'C', 'FirmataClass::setFirmwareNameAndVersion' +
          '(this=r25:r24, const char *name=r23:r22, byte major=r20, byte minor=r18)'),

    Label(0x0e50, 'C', 'FirmataClass::begin(this=r25:r24, long speed=r23:r22:r21:r20)'),

    Label(0x0e82, 'C', 'digitalWriteCallback(byte port=r24, int value=r23:r22)'),

    Label(0x0f48, 'C', 'reportAnalogCallback(byte analogPin=r24, int value=r23:r22)'),

    Label(0x0f96, 'C', 'reportDigitalCallback(byte port=r24, int value=r23:r22)'),

    Label(0x0fa6, 'C', 'sub_0fa6_cons2'),

    Label(0x0fc4, 'C', 'analogWriteCallback(byte pin=r24, int value=r23:r22)'),
    Label(0x0fe8, 'C', '_pinConfig[pin]==SERVO'),
    Label(0x1008, 'C', '_pinConfig[pin]==PWM'),
    Label(0x101c, 'c', 'analogWrite(PIN_TO_PWM(pin), value)'),
    Label(0x1024, 'C', '_pinState[pin] := r17:r16'),
    Label(0x1030, 'C', '_return'),

    Label(0x103a, 'C', 'sub_103a'),

    Label(0x108c, 'C', 'setPinModeCallback(byte pin=r24, int mode=r23:r22)'),

    Label(0x1340, 'C', 'sysexCallback(byte command=r24, byte argc=r22, byte *argv=r21:r20)'),

    Label(0x1616, 'C', 'outputPort(byte portNumber=r24, byte portValue=r22, byte forceSend=r20)'),
    Label(0x162a, 'c', 'r24 := portConfigInputs[portNumber]'),

    Label(0x165a, 'C', 'setup()'),

    Label(0x175a, 'C', 'checkDigitalInputs()'),

    Label(0x17a8, 'C', 'loop()'),

    Label(0x18ce, 'C', 'TIMER0_OVF_vect'),

    Label(0x195e, 'C', 'millis()->r25:r24:r23:r22'),

    Label(0x197a, 'C', 'delay(duration=r25:r24:r23:r22)'),

    Label(0x1a2c, 'C', 'initialize_ports()'),
    Label(0x1a46, 'c', 'Initialize timer'),

    Label(0x1aa2, 'C', 'analogRead(pin=r24)->r25:r24'),

    Label(0x1ae6, 'C', 'analogWrite(pwm=r24, value=r23:r22)'),

    Label(0x1ba6, 'C', 'pinMode(??)'),

    Label(0x1bf2, 'C', 'sub_1bf2'),

    Label(0x1ca2, 'C', 'USART_RX_vect'),
    Label(0x1cba, 'c', 'Read one byte from the serial to r20'),

    Label(0x1d04, 'C', 'Serial::begin(this=r25:r24, speed=r23:r22:r21:r20)'),
    Label(0x1d72, 'c', 'sbi(*_ucsrb, RXEN0)'),
    Label(0x1d8a, 'c', 'sbi(*_ucsrb, TXEN0)'),
    Label(0x1da0, 'c', 'sbi(*_ucsrb, RXCIE0)'),

    Label(0x1dbe, 'C', 'Serial::available(this=r25:r24)->r25:r24'),

    Label(0x1de0, 'C', 'Serial::peek(this=r25:r24)->r24'),

    Label(0x1e14, 'C', 'Serial::read(this=r25:r24)'),

    Label(0x1e5c, 'C', 'Serial::get_buffer_pos(this=r25:r24)->r25:r24'),

    Label(0x1e74, 'C', 'Serial::write(this=r25:r24, uint8_t c=r22)'),

    Label(0x1e9a, 'C', 'cons1_Serial::Serial(this=0x0361)'),

    Label(0x1f0e, 'C', 'main()'),

    Label(0x1f1c, 'C', 'Serial::write(this=r25:r24, const char *pszStr=r23:r22)'),

    Label(0x1f4c, 'C', 'Serial::write(this=r25:r24, const uint8_t *buffer=r23:r22, size_t size=r21:r20)'),

    Label(0x1f8a, 'C', 'sub_1f8a'),

    Label(0x20be, 'C', 'Serial.print(this=r25:r24, 4bytes-tosend=r23:r22:r21:r20, r19:r18=0)'),

    Label(0x20dc, 'C', 'Serial.print(this=r25:r24, bytetosend=r22, r21:r20=0)'),

    Label(0x2100, 'C', 'Serial.print(this=r25:r24, 4bytes-tosend=r23:r22:r21:r20, r19:r18=?)'),

    Label(0x216c, 'C', 'Serial.print(this=r25:r24, bytetosend=r23:r22, r21:r20=0)'),
    Label(0x2178, 'c', 'sign-extend r23:r22 to r17:r16:r15:r14'),

    # https://github.com/arduino/Arduino/blob/master/hardware/arduino/avr/cores/arduino/WMath.cpp
    Label(0x2192, 'C', 'map(x=r25:r24:r23:r22, in_min=r21:r20:r19:r18, in_max=r17:r16:r15:r14, ' +
          'out_min=r13:r12:r11:r10, out_max=sp+4:3:2:1)->r25:r24:r23:r22'),
    Label(0x21ca, 'c', 'r25:r24:r23:r22 = out_max - out_min'),
    Label(0x21d2, 'c', 'r9:r8:r7:r6 = x - in_min'),
    Label(0x21da, 'c', 'r25:r24:r23:r22 = (x-in_min) * (out_max-out_min)'),
    Label(0x21ea, 'c', 'r21:r20:r19:r18 = in_max - in_min'),
    Label(0x21fa, 'c', 'return (x-in_min)*(out_max-out_min)/(in_max-in_min)+out_min'),

    # Mathematic functions from GCC (libgcc/config/avr/lib1funcs.S)
    # https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=libgcc/config/avr/lib1funcs.S
    Label(0x2224, 'C', 'libgcc.__mulsi3(A=r25:r24:r23:r22, B=r21:r20:r19:r18)->r25:r24:r23:r22=A*B'),

    Label(0x2262, 'C', 'libgcc.udivmodqi4(dividend=r24, divisor=r22)->r25=r,r24=q'),
    Label(0x2268, 'C', '__udivmodqi4_loop'),
    Label(0x2270, 'C', '__udivmodqi4_ep'),

    Label(0x227a, 'C', 'libgcc.divmodhi4(dividend=r25:r24, divisor=r23:r22)->25:r24=r,r23:r22=q'),
    Label(0x228e, 'C', '__divmodhi4_neg1(negate r23:r22)'),
    Label(0x2296, 'C', '__divmodhi4_neg2(negate r25:r24)'),

    Label(0x22a0, 'C', 'libgcc.udivmodsi4(dividend=r25:r24:r23:r22, divisor=r21:r20:r19:r18)' +
          '->r25:r24:r23:r22=r,r21:r20:r19:r18=q'),
    Label(0x22ac, 'C', '__udivmodsi4_loop'),
    Label(0x22c6, 'C', '__udivmodsi4_ep'),

    Label(0x22e4, 'C', 'libgcc.divmodsi4(dividend=r25:r24:r23:r22, divisor=r21:r20:r19:r18)' +
          '->r25:r24:r23:r22=r,r21:r20:r19:r18=q'),
    Label(0x22f8, 'C', '__divmodsi4_neg2(negate 21:r20:r19:r18)'),
    Label(0x2306, 'C', '__divmodsi4_exit'),
    Label(0x2308, 'C', '__negsi2(negate 25:r24:r23:r22)'),

    Label(0x231a, 'C', 'libgcc.udivmodhi4(dividend=r25:r24, divisor=r23:r22)->25:r24=r,r23:r22=q'),
    Label(0x2322, 'C', '__udivmodhi4_loop'),
    Label(0x2330, 'C', '__udivmodhi4_ep'),

    Label(0x2346, 'C', 'call_constructor(fctptr=r31:r30)'),

    Label(0x234e, 'C', 'exit()'),
    Label(0x2350, 'C', '_loop_forever'),

    # Firmware application data, copied in RAM at 0x100..0x1ee
    Label(0x2352, 'D', '".cpp"'),
    Label(0x2357, 'D', '"Servo only on pins from 2 to 13"'),
    Label(0x2377, 'D', '"I2C mode not yet supported"'),
    Label(0x2392, 'D', '"Unknown pin mode"'),
    Label(0x23a3, 'D', '"Not enough data"'),
    Label(0x23b3, 'D', '"/var/.../StandardFirmata_2_2_forUNO_0_3.cpp"'),
    Label(0x2425, 'D', '__malloc_margin_L'),
    Label(0x2426, 'D', '__malloc_margin_H'),
    Label(0x2427, 'D', '__malloc_heap_start_L'),
    Label(0x2428, 'D', '__malloc_heap_start_H'),
    Label(0x2429, 'D', '__malloc_heap_end_L'),
    Label(0x242a, 'D', '__malloc_heap_end_H'),

    Label(0x2432, 'J', 'Serial_vtable'),
    Label(0x2440, 'D', 'end_of_.data'),

    # Label(0x2440, 'D', '"qM/qMbRSV3C2RaR-E+BYpHBZ++++TM/-Tmp-/build7212209529473679272.tm(/0"'),
    Label(0x2ac4, 'D', '"Received SMS from "'),
    Label(0x2ad7, 'D', '"(sim position: "'),
    Label(0x2ae7, 'D', '")"'),
    Label(0x2ae9, 'D', '"SMS deleted"'),
    Label(0x2af5, 'D', '"SMS not deleted"'),
    Label(0x2b05, 'D', '"no call"'),
    Label(0x2b0d, 'D', '"incoming voice call from "'),
    Label(0x2b27, 'D', '"active voice call"'),
    Label(0x2b39, 'D', '"no response"'),
    Label(0x2b45, 'D', '"Command: "'),
    Label(0x2b4f, 'D', '"Check_Protocol"'),
    Label(0x2b5e, 'D', '"Answer"'),
    Label(0x2b65, 'D', '"No incoming call"'),
    Label(0x2b76, 'D', '"Calling "'),
    Label(0x2b7f, 'D', '"No number in pos "'),
    Label(0x2b91, 'D', '"Hang"'),
    Label(0x2b96, 'D', '"Send SMS to "'),
    Label(0x2ba3, 'D', '"SMS ERROR "'),
    Label(0x2baf, 'D', '"SMS OK "'),
    Label(0x2bb8, 'D', '"Phone number position "'),
    Label(0x2bcf, 'D', '" deleted"'),
    Label(0x2bd8, 'D', '"Phone Book position "'),
    Label(0x2bf0, 'D', '"No Phone number in position "'),
    Label(0x2c0d, 'D', '"Number "'),
    Label(0x2c15, 'D', '" writed in Phone Book position "'),
    Label(0x2c35, 'D', '"Writing error"'),
    Label(0x2c43, 'D', '"system startup"'),
    Label(0x2c60, 'D', '"AT+CPBW="'),
    Label(0x2c69, 'D', '"OK"'),
    Label(0x2c6c, 'D', '",\\".\\"\\r"'),
    Label(0x2c72, 'D', '"AT+CPBR="'),
    Label(0x2c7b, 'D', '"+CPBR"'),
    Label(0x2c81, 'D', '"AT+CMGD="'),
    Label(0x2c8a, 'D', '"AT+CMGR="'),
    Label(0x2c93, 'D', '"+CMGR"'),
    Label(0x2c99, 'D', '""REC UNREAD""'),
    Label(0x2ca6, 'D', '""REC READ""'),
    Label(0x2cb1, 'D', '"AT+CMGS=""'),
    Label(0x2cbd, 'D', '"+CMGS"'),
    Label(0x2cc3, 'D', '"AT+CLCC"'),
    Label(0x2cd0, 'D', '"+CLCC: 1,1,4,0,0"'),
    Label(0x2ce1, 'D', '"+CLCC: 1,1,4,1,0"'),
    Label(0x2cf2, 'D', '"+CLCC: 1,0,0,0,0"'),
    Label(0x2d03, 'D', '"+CLCC: 1,1,0,0,0"'),
    Label(0x2d14, 'D', '"+CLCC: 1,1,0,1,0"'),
    Label(0x2d25, 'D', '"+CLCC:"'),
    Label(0x2d2c, 'D', '"AT+VTS="'),
    Label(0x2d34, 'D', '"AT+CLVL="'),
    Label(0x2d3d, 'D', '"ATD>"SM" "'),
    Label(0x2d4e, 'D', '"AT+CPAS"'),
    Label(0x2d5c, 'D', '"AT+CSQ"'),
    Label(0x2d63, 'D', '"\\t+CSQ:"'),
    Label(0x2d6a, 'D', '"AT+CNMI=2,0"'),
    Label(0x2d76, 'D', '"AT+CPMS="SM","SM","SM""'),
    Label(0x2d8d, 'D', '"+CPMS:"'),
    Label(0x2d94, 'D', '"AT&F"'),
    Label(0x2d99, 'D', '"AT+CLIP=1"'),
    Label(0x2da3, 'D', '"AT+CMEE=0"'),
    Label(0x2dad, 'D', '"AT+CMGF=1"'),
    Label(0x2db7, 'D', '"AT+CPBS="SM""'),
    Label(0x2dc7, 'D', '"AT+IPR="'),
    Label(0x2dcf, 'D', '"AT+CREG?"'),
    Label(0x2dd8, 'D', '"+CREG: 0,1"'),
    Label(0x2de3, 'D', '"+CREG: 0,5"'),
    Label(0x2dee, 'D', '"AT+CMGL="REC UNREAD""'),
    Label(0x2e04, 'D', '"AT+CMGL="REC READ""'),
    Label(0x2e18, 'D', '"AT+CMGL="ALL""'),
    Label(0x2e27, 'D', '"+CMGL:"'),
    Label(0x2e35, 'D', '"+393459932108"'),
    Label(0x2e43, 'D', '"hello world"'),
    Label(0x2e6e, 'D', '"AT+CMGL="REC UNREAD""'),
    Label(0x2e84, 'D', '"AT+CMGL="ALL""'),
    Label(0x2e93, 'D', '"+CMGL:"'),
    Label(0x2ea1, 'D', '"+393453054796"'),
    Label(0x2eaf, 'D', '"hello world"'),
    Label(0x2eda, 'D', '"AT+CMGL="REC UNREAD""'),
    Label(0x2ef0, 'D', '"AT+CMGL="REC REA"'),
    Label(0x2fce, 'D', '"!P0@@@P@V"'),
    Label(0x308c, 'D', '"/s0p"'),
    Label(0x315f, 'D', '"@/_?O/s0p"'),
    Label(0x340e, 'D', '"Initializing SD card..."'),
    Label(0x3426, 'D', '"initialization failed!"'),
    Label(0x343d, 'D', '"initialization done."'),
    Label(0x3452, 'D', '"test.txt"'),
    Label(0x345b, 'D', '"Writing to test.txt..."'),
    Label(0x3472, 'D', '"testing 1, 2, 3."'),
    Label(0x3483, 'D', '"done."'),
    Label(0x3489, 'D', '"error opening test.txt"'),
    Label(0x34a0, 'D', '"test.txt:"'),
    Label(0x34aa, 'D', '"/"'),
    Label(0x34ac, 'D', '" "'),
    Label(0x34de, 'D', '"ting to test.txt..."'),
    Label(0x34f2, 'D', '"testing 1, 2, "'),
    Label(0x3500, 'p'),
]

# Add SRAM labels for data section
SRAM_LABELS = [
    Label(0x1ee, 'R', 'ServoCount'),  # uint8_t ServoCount in Servo.cpp
    # https://github.com/arduino/Arduino/blob/master/libraries/Servo/src/Servo.h
    Label(0x1ef, 'R', 'servos[0].Pin'),  # servos is an array of 12 servo_t
    Label(0x1f0, 'R', 'servos[0].ticks_L'),
    Label(0x1f1, 'R', 'servos[0].ticks_H'),
    Label(0x1f2, 'R', 'servos[1].Pin'),
    Label(0x1f3, 'R', 'servos[1].ticks_L'),
    Label(0x1f4, 'R', 'servos[1].ticks_H'),
    Label(0x1f5, 'R', 'servos[2].Pin'),
    Label(0x1f6, 'R', 'servos[2].ticks_L'),
    Label(0x1f7, 'R', 'servos[2].ticks_H'),
    Label(0x1f8, 'R', 'servos[3].Pin'),
    Label(0x1f9, 'R', 'servos[3].ticks_L'),
    Label(0x1fa, 'R', 'servos[3].ticks_H'),
    Label(0x1fb, 'R', 'servos[4].Pin'),
    Label(0x1fc, 'R', 'servos[4].ticks_L'),
    Label(0x1fd, 'R', 'servos[4].ticks_H'),
    Label(0x1fe, 'R', 'servos[5].Pin'),
    Label(0x1ff, 'R', 'servos[5].ticks_L'),
    Label(0x200, 'R', 'servos[5].ticks_H'),
    Label(0x201, 'R', 'servos[6].Pin'),
    Label(0x202, 'R', 'servos[6].ticks_L'),
    Label(0x203, 'R', 'servos[6].ticks_H'),
    Label(0x205, 'R', 'servos[7].Pin'),
    Label(0x206, 'R', 'servos[7].ticks_L'),
    Label(0x207, 'R', 'servos[7].ticks_H'),
    Label(0x208, 'R', 'servos[8].Pin'),
    Label(0x209, 'R', 'servos[8].ticks_L'),
    Label(0x20a, 'R', 'servos[8].ticks_H'),
    Label(0x20b, 'R', 'servos[9].Pin'),
    Label(0x20c, 'R', 'servos[9].ticks_L'),
    Label(0x20d, 'R', 'servos[9].ticks_H'),
    Label(0x20e, 'R', 'servos[10].Pin'),
    Label(0x20f, 'R', 'servos[10].ticks_L'),
    Label(0x210, 'R', 'servos[10].ticks_H'),
    Label(0x211, 'R', 'servos[11].Pin'),
    Label(0x212, 'R', 'servos[11].ticks_L'),
    Label(0x213, 'R', 'servos[11].ticks_H'),

    Label(0x214, 'R', '*Firmata'),  # Firmata object

    Label(0x251, 'R', 'analogInputsToReport_L'),
    Label(0x252, 'R', 'analogInputsToReport_H'),
    Label(0x253, 'R', 'reportPINs[0]'),
    Label(0x254, 'R', 'reportPINs[1]'),
    Label(0x255, 'R', 'reportPINs[2]'),
    Label(0x256, 'R', 'previousPINs[0]'),
    Label(0x257, 'R', 'previousPINs[1]'),
    Label(0x258, 'R', 'previousPINs[2]'),
    Label(0x259, 'R', 'pinConfig[0]'),
    Label(0x25a, 'R', 'pinConfig[1]'),
    Label(0x271, 'R', 'portConfigInputs[0]'),
    Label(0x272, 'R', 'portConfigInputs[1]'),
    Label(0x273, 'R', 'portConfigInputs[2]'),
    Label(0x274, 'R', 'pinState[0]L'),
    Label(0x275, 'R', 'pinState[0]H'),
    Label(0x276, 'R', 'pinState[1]L'),
    Label(0x277, 'R', 'pinState[1]H'),

    Label(0x2b0, 'R', 'servos[0]_L'),  # Address of servos[0] object
    Label(0x2b1, 'R', 'servos[0]_H'),

    Label(0x2d4, 'R', 'timer0_overflow_count_LL'),
    Label(0x2d5, 'R', 'timer0_overflow_count_LH'),
    Label(0x2d6, 'R', 'timer0_overflow_count_HL'),
    Label(0x2d7, 'R', 'timer0_overflow_count_HH'),
    Label(0x2d8, 'R', 'timer0_millis_LL'),
    Label(0x2d9, 'R', 'timer0_millis_LH'),
    Label(0x2da, 'R', 'timer0_millis_HL'),
    Label(0x2db, 'R', 'timer0_millis_HH'),
    Label(0x2dc, 'R', 'timer0_fract'),

    Label(0x2dd, 'R', 'HardwareSerial._rx_buffer'),  # Reception buffer, 128 bytes
    Label(0x35d, 'R', 'HardwareSerial._rx_buffer_head_L'),  # Received bytes are written here
    Label(0x35e, 'R', 'HardwareSerial._rx_buffer_head_H'),
    Label(0x35f, 'R', 'HardwareSerial._rx_buffer_tail_L'),  # Received bytes are read here
    Label(0x360, 'R', 'HardwareSerial._rx_buffer_tail_H'),

    Label(0x361 + 0x00, 'R', 'Serial'),  # Serial object; also address of low byte of virtual fcts ptrs
    Label(0x361 + 0x01, 'R', 'Serial.vtable_H'),
    Label(0x361 + 0x02, 'R', 'Serial.hwserial_mem_L'),  # Address of HardwareSerial variables
    Label(0x361 + 0x03, 'R', 'Serial.hwserial_mem_H'),
    Label(0x361 + 0x04, 'R', 'Serial._ubrrh_L'),  # Pointer to USART Baud Rate Register
    Label(0x361 + 0x05, 'R', 'Serial._ubrrh_H'),
    Label(0x361 + 0x06, 'R', 'Serial._ubrrl_L'),
    Label(0x361 + 0x07, 'R', 'Serial._ubrrl_H'),
    Label(0x361 + 0x08, 'R', 'Serial._ucsra_L'),
    Label(0x361 + 0x09, 'R', 'Serial._ucsra_H'),
    Label(0x361 + 0x0a, 'R', 'Serial._ucsrb_L'),
    Label(0x361 + 0x0b, 'R', 'Serial._ucsrb_H'),
    Label(0x361 + 0x0c, 'R', 'Serial._udr_L'),  # Data Register
    Label(0x361 + 0x0d, 'R', 'Serial._udr_H'),
    Label(0x361 + 0x0e, 'R', 'Serial._RXEN0'),  # Enable RX in UCSR0B (bitpos)
    Label(0x361 + 0x0f, 'R', 'Serial._TXEN0'),  # Enable TX in UCSR0B
    Label(0x361 + 0x10, 'R', 'Serial._RXCIE0'),  # ?, in UCSR0B
    Label(0x361 + 0x11, 'R', 'Serial._UDRE0'),  # DR Enable, TX is possible (in UCSR0A)

    Label(0x374, 'R', 'Heap.__brkval_L'),
    Label(0x375, 'R', 'Heap.__brkval_H'),
    Label(0x376, 'R', 'Heap.__freelistp_L'),
    Label(0x377, 'R', 'Heap.__freelistp_H'),
    Label(0x378, 'R', 'Heap.start'),
    Label(0x8ff, 'R', '__stack'),
]
DATA_LABELS = []
for lab in LABELS:
    if 0x2352 <= lab.addr < 0x2352 + 0x1ee - 0x100:
        DATA_LABELS.append(Label(lab.addr - 0x2352 + 0x100, 'R', lab.name))
LABELS += DATA_LABELS + SRAM_LABELS


def decode(filepath, labels):
    """Decode the firmata part of the specified ihex file"""
    assert utils.check_labels_order(labels)
    fwmem = utils.load_ihex(filepath)
    assert fwmem is not None

    meta = ATmega328PMeta(fwmem, labels)

    # First pass: find every code label
    brdict = meta.get_branch_targets()
    for addr, is_call in brdict.items():
        if addr not in meta.labels:
            name = '{}_{:04x}'.format('sub' if is_call else '_loc', addr)
            meta.labels[addr] = Label(addr, 'C', name)

    # Second pass: dump everything
    meta.show_all()

if __name__ == '__main__':
    decode(os.path.join(os.path.dirname(__file__), 'initialflash.hex'), LABELS)
