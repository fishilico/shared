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
"""Decode the initial bootloader code on an Arduino Uno, which is optiboot

https://code.google.com/p/optiboot/source/browse/optiboot/bootloaders/optiboot/optiboot.c

@author: Nicolas Iooss
@license: MIT
"""
import os.path
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import utils  # noqa
from atmega328p import ATmega328PMeta, Label  # noqa


# Optiboot labels
LABELS = [
    # Rename some I/O ports
    Label(0x03, 'P', 'LED_PIN'),  # PINB
    Label(0x04, 'P', 'LED_DDR'),  # DDRB
    Label(0x05, 'P', 'LED_PORT'),  # PORTB

    Label(0x7e00, 'C', 'main()'),
    Label(0x7e0a, 'c', 'TCCR1B = _BV(CS12) | _BV(CS10), set up timer 1'),
    Label(0x7e10, 'c', 'UART_SRA = _BV(U2X0), double speed mode USART0'),
    Label(0x7e16, 'c', 'UART_SRB = _BV(RXEN0) | _BV(TXEN0), enable RX/TX'),
    Label(0x7e1c, 'c', 'UART_SRC = _BV(UCSZ00) | _BV(UCSZ01)'),
    Label(0x7e22, 'c', 'Set up UART baud rate'),
    Label(0x7e28, 'c', 'watchdogConfig(WATCHDOG_1S)'),
    Label(0x7e2c, 'c', 'LED_DDR |= _BV(LED), set LED pin as output'),
    Label(0x7e2e, 'C', '_flash_led(count=6)'),
    Label(0x7e2e, 'c', 'Flash LED 3 times'),
    Label(0x7e36, 'C', '__loop_flashled'),
    Label(0x7e40, 'c', 'wait_for(TIFR1 & _BV(TOV1))'),
    Label(0x7e60, 'C', '_forever_loop'),
    Label(0x7e66, 'C', '_if(ch==STK_GET_PARAMETER)'),
    Label(0x7e74, 'C', '__STK_GET_PARAMETER,0x82 or 0x81'),
    Label(0x7e78, 'C', '__STK_GET_PARAMETER,other'),
    Label(0x7e7a, 'C', '__STK_GET_PARAMETER:putch'),
    Label(0x7e7a, 'c', 'putch(optiboot version 4.4)'),
    Label(0x7e7e, 'C', '_else...'),
    Label(0x7e82, 'C', '_if(ch == STK_SET_DEVICE)'),
    Label(0x7e86, 'C', '_else...'),
    Label(0x7e8a, 'C', '_if(ch == STK_SET_DEVICE_EXT)'),
    Label(0x7e8c, 'C', '__getNch'),
    Label(0x7e8c, 'c', 'Ignore SET_DEVICE*'),
    Label(0x7e90, 'C', '_else...'),
    Label(0x7e94, 'C', '_if(ch == STK_LOAD_ADDRESS)'),
    Label(0x7e9c, 'c', 'r17:r16 = (read 2 bytes) * 2'),
    Label(0x7eae, 'c', 'r13:r12 = new address'),
    Label(0x7eb2, 'C', '_else...'),
    Label(0x7eb6, 'C', '_if(ch == STK_UNIVERSAL)'),
    Label(0x7ebe, 'C', '_else...'),
    Label(0x7ec4, 'C', '_if(ch == STK_PROG_PAGE)'),
    Label(0x7ec8, 'c', 'r16 = length'),
    Label(0x7ed6, 'C', '__if(r13:r12 < 0x7000)'),
    Label(0x7ed6, 'c', 'Erase Flash memory at r13:r12'),
    Label(0x7edc, 'C', '__endif'),
    Label(0x7ee0, 'C', '__loop_get_page'),
    Label(0x7ee0, 'c', 'Read bytes in 0x0100'),
    Label(0x7ef2, 'C', '__if(r13:r12 >= 0x7000)'),
    Label(0x7ef2, 'c', 'Erase Flash memory at r13:r12'),
    Label(0x7ef8, 'C', '__endif'),
    Label(0x7efa, 'C', '__loop_spm_busy_wait'),
    Label(0x7f06, 'C', '__loop_copy'),
    Label(0x7f06, 'c', 'Copy SRAM@0x0100 to Flash@r13:12'),
    Label(0x7f1c, 'c', 'Store r25:r24 into Programming Buffer@r21:r20'),
    Label(0x7f2c, 'c', '... repeat until r27:r26 reaches 0x180'),
    Label(0x7f32, 'c', 'Write programming buffer'),
    Label(0x7f38, 'C', '__loop_spm_busy_wait'),
    Label(0x7f3e, 'c', 'Reable read access to the flash'),
    Label(0x7f44, 'C', '_else...'),
    Label(0x7f48, 'C', '_if(ch == STK_READ_PAGE)'),
    Label(0x7f56, 'C', '__loop_read_progmem_to_uart'),
    Label(0x7f74, 'C', '_else...'),
    Label(0x7f78, 'C', '_if(ch == STK_READ_SIGN)'),
    Label(0x7f7a, 'c', '"Read signature" command, putch 3 bytes'),
    Label(0x7f86, 'C', '_else...'),
    Label(0x7f8a, 'C', '_if(ch == \'Q\')'),
    Label(0x7f8a, 'c', 'watchdogConfig(WATCHDOG_16MS)'),
    Label(0x7f8e, 'C', '_else'),
    Label(0x7f90, 'C', '_endif(ch)'),

    Label(0x7f96, 'C', 'putch(r24, r25)'),
    Label(0x7f98, 'C', '_loop'),
    Label(0x7f9c, 'c', 'loop_while(!(UCSR0A & _BV(UDRE0))'),

    Label(0x7fa6, 'C', 'getch()->r24'),
    Label(0x7faa, 'c', 'loop_while(!(UCSR0A & _BV(RXC0)))'),
    Label(0x7fb6, 'c', 'if(!(UCSR0A & _BV(FE0))) wdr (if frame error, reset)'),
    Label(0x7fb8, 'C', '_endif'),

    Label(0x7fbe, 'C', 'watchdogConfig(r24)'),
    Label(0x7fbe, 'c', 'WDTCSR = _BV(WDCE) | _BV(WDE)'),
    Label(0x7fc6, 'c', 'WDTCSR = r24'),

    Label(0x7fca, 'C', 'verifySpace'),
    Label(0x7fd0, 'c', 'watchdogConfig(WATCHDOG_16MS)'),
    Label(0x7fd6, 'C', '_end_if(getch() != space)'),
    Label(0x7fd6, 'c', 'putch(STK_INSYNC)'),

    Label(0x7fda, 'C', 'getNch(r24=count)'),
    Label(0x7fde, 'C', '_loop_getch'),

    Label(0x7fea, 'C', 'appStart'),
    Label(0x7fea, 'c', 'watchdogConfig(WATCHDOG_OFF)'),
    Label(0x7fee, 'c', 'Start application at 0000'),

    Label(0x7ff4, 'D', 'padding'),
    Label(0x7ffe, 'D', 'optiboot_version'),
]


def decode(filepath, labels):
    """Decode the optiboot part of the specified ihex file"""
    assert utils.check_labels_order(labels)
    fwmem = utils.load_ihex(filepath)
    assert fwmem is not None

    meta = ATmega328PMeta(fwmem, labels)
    meta.show_all(0x7e00)


if __name__ == '__main__':
    decode(os.path.join(os.path.dirname(__file__), 'initialflash.hex'), LABELS)
