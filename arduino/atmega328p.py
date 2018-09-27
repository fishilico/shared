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
"""Define some constants specific to the ATmega328P CPU

Thus CPU is used for example in Arduino Uno

AVR-libc include file (installed in /usr/avr/include/avr/iom328p.h):
http://svn.savannah.nongnu.org/viewvc/trunk/avr-libc/include/avr/iom328p.h?root=avr-libc&view=markup

@author: Nicolas Iooss
@license: MIT
"""
# pylint: disable=unused-import
from avr8bit_instructions import AVR8Meta, Label  # noqa

# Ports
# sed -n "s/# *define \([^ ]*\)  *_SFR_IO8(0x\(.*\))/    0x\2: '\1',/p" \
#    /usr/avr/include/avr/{iom328p.h,common.h}
PORTS = {
    0x03: 'PINB',
    0x04: 'DDRB',
    0x05: 'PORTB',
    0x06: 'PINC',
    0x07: 'DDRC',
    0x08: 'PORTC',
    0x09: 'PIND',
    0x0A: 'DDRD',
    0x0B: 'PORTD',
    0x15: 'TIFR0',
    0x16: 'TIFR1',
    0x17: 'TIFR2',
    0x1B: 'PCIFR',
    0x1C: 'EIFR',
    0x1D: 'EIMSK',
    0x1E: 'GPIOR0',
    0x1F: 'EECR',
    0x20: 'EEDR',
    0x21: 'EEARL',
    0x22: 'EEARH',
    0x23: 'GTCCR',
    0x24: 'TCCR0A',
    0x25: 'TCCR0B',
    0x26: 'TCNT0',
    0x27: 'OCR0A',
    0x28: 'OCR0B',
    0x2A: 'GPIOR1',
    0x2B: 'GPIOR2',
    0x2C: 'SPCR',
    0x2D: 'SPSR',
    0x2E: 'SPDR',
    0x30: 'ACSR',
    0x33: 'SMCR',
    0x34: 'MCUSR',
    0x35: 'MCUCR',
    0x37: 'SPMCSR',
    0x3D: 'SPL',  # Stack Pointer Register (Low byte)
    0x3E: 'SPH',  # Stack Pointer Register (High byte)
    0x3F: 'SREG',  # Status register
}

# Registers in SRAM
# sed -n "s/# *define \([^ ]*\)  *_SFR_MEM8(0x\(.*\))/    0x\2: '\1',/p" \
#    /usr/avr/include/avr/iom328p.h
SRAM_REGS = {
    0x60: 'WDTCSR',  # Watchdog Timer's Control Register
    0x61: 'CLKPR',
    0x64: 'PRR',
    0x66: 'OSCCAL',
    0x68: 'PCICR',
    0x69: 'EICRA',
    0x6B: 'PCMSK0',
    0x6C: 'PCMSK1',
    0x6D: 'PCMSK2',
    0x6E: 'TIMSK0',
    0x6F: 'TIMSK1',
    0x70: 'TIMSK2',
    0x78: 'ADCL',
    0x79: 'ADCH',
    0x7A: 'ADCSRA',
    0x7B: 'ADCSRB',
    0x7C: 'ADMUX',
    0x7E: 'DIDR0',
    0x7F: 'DIDR1',
    0x80: 'TCCR1A',
    0x81: 'TCCR1B',
    0x82: 'TCCR1C',
    0x84: 'TCNT1L',
    0x85: 'TCNT1H',
    0x86: 'ICR1L',
    0x87: 'ICR1H',
    0x88: 'OCR1AL',
    0x89: 'OCR1AH',
    0x8A: 'OCR1BL',
    0x8B: 'OCR1BH',
    0xB0: 'TCCR2A',
    0xB1: 'TCCR2B',
    0xB2: 'TCNT2',
    0xB3: 'OCR2A',
    0xB4: 'OCR2B',
    0xB6: 'ASSR',
    0xB8: 'TWBR',
    0xB9: 'TWSR',
    0xBA: 'TWAR',
    0xBB: 'TWDR',
    0xBC: 'TWCR',
    0xBD: 'TWAMR',
    0xC0: 'UCSR0A',  # UART_SRA, UART control register
    0xC1: 'UCSR0B',  # UART_SRB
    0xC2: 'UCSR0C',  # UART_SRC
    0xC4: 'UBRR0L',  # UART_SRL
    0xC5: 'UBRR0H',  # UART_SRH
    0xC6: 'UDR0',  # UART Data Register
}

# Interrupt Vectors
# sed -n "s/# *define \([^ ]*\)  *_VECTOR(\(.*\))/    \2: '\1',/p" \
# /usr/avr/include/avr/iom328p.h | sed 's;, */\*\(.*\) \*/.*;,  #\1;'
VECTORS = {
    0: 'reset_vect',  # Reset vector, also used at boot time
    1: 'INT0_vect',  # External Interrupt Request 0
    2: 'INT1_vect',  # External Interrupt Request 1
    3: 'PCINT0_vect',  # Pin Change Interrupt Request 0
    4: 'PCINT1_vect',  # Pin Change Interrupt Request 0
    5: 'PCINT2_vect',  # Pin Change Interrupt Request 1
    6: 'WDT_vect',  # Watchdog Time-out Interrupt
    7: 'TIMER2_COMPA_vect',  # Timer/Counter2 Compare Match A
    8: 'TIMER2_COMPB_vect',  # Timer/Counter2 Compare Match A
    9: 'TIMER2_OVF_vect',  # Timer/Counter2 Overflow
    10: 'TIMER1_CAPT_vect',  # Timer/Counter1 Capture Event
    11: 'TIMER1_COMPA_vect',  # Timer/Counter1 Compare Match A
    12: 'TIMER1_COMPB_vect',  # Timer/Counter1 Compare Match B
    13: 'TIMER1_OVF_vect',  # Timer/Counter1 Overflow
    14: 'TIMER0_COMPA_vect',  # TimerCounter0 Compare Match A
    15: 'TIMER0_COMPB_vect',  # TimerCounter0 Compare Match B
    16: 'TIMER0_OVF_vect',  # Timer/Couner0 Overflow
    17: 'SPI_STC_vect',  # SPI Serial Transfer Complete
    18: 'USART_RX_vect',  # USART Rx Complete
    19: 'USART_UDRE_vect',  # USART, Data Register Empty
    20: 'USART_TX_vect',  # USART Tx Complete
    21: 'ADC_vect',  # ADC Conversion Complete
    22: 'EE_READY_vect',  # EEPROM Ready
    23: 'ANALOG_COMP_vect',  # Analog Comparator
    24: 'TWI_vect',  # Two-wire Serial Interface
    25: 'SPM_READY_vect',  # Store Program Memory Read
}


class ATmega328PMeta(AVR8Meta):
    """Specific meta-information to decode an ATmega328P firmware"""

    def __init__(self, fwmem, labels):
        super(ATmega328PMeta, self).__init__(fwmem, labels)
        self.add_cpu_data(PORTS, SRAM_REGS, VECTORS)
