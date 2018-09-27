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
"""Define some constants specific to the ATmega32U4 CPU

Thus CPU is used for example in Arduino Micro

AVR-libc include file (installed in /usr/avr/include/avr/iom32u4.h):
http://svn.savannah.nongnu.org/viewvc/trunk/avr-libc/include/avr/iom32u4.h?root=avr-libc&view=markup

@author: Nicolas Iooss
@license: MIT
"""
# pylint: disable=unused-import
from avr8bit_instructions import AVR8Meta, Label  # noqa

# Ports
# sed -n "s/# *define \([^ ]*\)  *_SFR_IO8(0x\(.*\))/    0x\2: '\1',/p" \
#    /usr/avr/include/avr/iom32u4.h
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
    0x0C: 'PINE',
    0x0D: 'DDRE',
    0x0E: 'PORTE',
    0x0F: 'PINF',
    0x10: 'DDRF',
    0x11: 'PORTF',
    0x15: 'TIFR0',
    0x16: 'TIFR1',
    0x18: 'TIFR3',
    0x19: 'TIFR4',
    0x1A: 'TIFR5',
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
    0x29: 'PLLCSR',
    0x2A: 'GPIOR1',
    0x2B: 'GPIOR2',
    0x2C: 'SPCR',
    0x2D: 'SPSR',
    0x2E: 'SPDR',
    0x30: 'ACSR',
    0x31: 'OCDR',
    0x32: 'PLLFRQ',
    0x33: 'SMCR',
    0x34: 'MCUSR',
    0x35: 'MCUCR',
    0x37: 'SPMCSR',
    0x3B: 'RAMPZ',
    0x3C: 'EIND',
    0x3D: 'SPL',  # Stack Pointer Register (Low byte)
    0x3E: 'SPH',  # Stack Pointer Register (High byte)
    0x3F: 'SREG',  # Status register
}

# Registers in SRAM
# sed -n "s/# *define \([^ ]*\)  *_SFR_MEM8(0x\(.*\)).*/    0x\2: '\1',/p" \
#    /usr/avr/include/avr/iom32u4.h
SRAM_REGS = {
    0x60: 'WDTCSR',  # Watchdog Timer's Control Register
    0x61: 'CLKPR',
    0x64: 'PRR0',
    0x65: 'PRR1',
    0x66: 'OSCCAL',
    0x67: 'RCCTRL',
    0x68: 'PCICR',
    0x69: 'EICRA',
    0x6A: 'EICRB',
    0x6B: 'PCMSK0',
    0x6C: 'PCMSK1',
    0x6D: 'PCMSK2',
    0x6E: 'TIMSK0',
    0x6F: 'TIMSK1',
    0x70: 'TIMSK2',
    0x71: 'TIMSK3',
    0x72: 'TIMSK4',
    0x73: 'TIMSK5',
    0x78: 'ADCL',
    0x79: 'ADCH',
    0x7A: 'ADCSRA',
    0x7B: 'ADCSRB',
    0x7C: 'ADMUX',
    0x7D: 'DIDR2',
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
    0x8C: 'OCR1CL',
    0x8D: 'OCR1CH',
    0x90: 'TCCR3A',
    0x91: 'TCCR3B',
    0x92: 'TCCR3C',
    0x94: 'TCNT3L',
    0x95: 'TCNT3H',
    0x96: 'ICR3L',
    0x97: 'ICR3H',
    0x98: 'OCR3AL',
    0x99: 'OCR3AH',
    0x9A: 'OCR3BL',
    0x9B: 'OCR3BH',
    0x9C: 'OCR3CL',
    0x9D: 'OCR3CH',
    0x9E: 'UHCON',
    0x9F: 'UHINT',
    0xA0: 'UHIEN',
    0xA1: 'UHADDR',
    0xA2: 'UHFNUML',
    0xA3: 'UHFNUMH',
    0xA4: 'UHFLEN',
    0xA5: 'UPINRQX',
    0xA6: 'UPINTX',
    0xA7: 'UPNUM',
    0xA8: 'UPRST',
    0xA9: 'UPCONX',
    0xAA: 'UPCFG0X',
    0xAB: 'UPCFG1X',
    0xAC: 'UPSTAX',
    0xAD: 'UPCFG2X',
    0xAE: 'UPIENX',
    0xAF: 'UPDATX',
    0xB8: 'TWBR',
    0xB9: 'TWSR',
    0xBA: 'TWAR',
    0xBB: 'TWDR',
    0xBC: 'TWCR',
    0xBD: 'TWAMR',
    0xBE: 'TCNT4L',
    0xBF: 'TCNT4H',  # = TC4H
    0xC0: 'TCCR4A',
    0xC1: 'TCCR4B',
    0xC2: 'TCCR4C',
    0xC3: 'TCCR4D',
    0xC4: 'TCCR4E',
    0xC5: 'CLKSEL0',
    0xC6: 'CLKSEL1',
    0xC7: 'CLKSTA',
    0xC8: 'UCSR1A',
    0xC9: 'UCSR1B',
    0xCA: 'UCSR1C',
    0xCB: 'UCSR1D',
    0xCC: 'UBRR1L',
    0xCD: 'UBRR1H',
    0xCE: 'UDR1',
    0xCF: 'OCR4A',
    0xD0: 'OCR4B',
    0xD1: 'OCR4C',
    0xD2: 'OCR4D',
    0xD4: 'DT4',
    0xD7: 'UHWCON',
    0xD8: 'USBCON',
    0xD9: 'USBSTA',
    0xDA: 'USBINT',
    0xDD: 'OTGCON',
    0xDE: 'OTGIEN',
    0xDF: 'OTGINT',
    0xE0: 'UDCON',
    0xE1: 'UDINT',
    0xE2: 'UDIEN',
    0xE3: 'UDADDR',
    0xE4: 'UDFNUML',
    0xE5: 'UDFNUMH',
    0xE6: 'UDMFN',
    0xE7: 'UDTST',
    0xE8: 'UEINTX',
    0xE9: 'UENUM',
    0xEA: 'UERST',
    0xEB: 'UECONX',
    0xEC: 'UECFG0X',
    0xED: 'UECFG1X',
    0xEE: 'UESTA0X',
    0xEF: 'UESTA1X',
    0xF0: 'UEIENX',
    0xF1: 'UEDATX',
    0xF2: 'UEBCLX',
    0xF3: 'UEBCHX',
    0xF4: 'UEINT',
    0xF5: 'UPERRX',
    0xF6: 'UPBCLX',
    0xF7: 'UPBCHX',
    0xF8: 'UPINT',
    0xF9: 'OTGTCON',
}

# Interrupt Vectors
# sed -n "s/# *define \([^ ]*\)  *_VECTOR(\(.*\))/    \2: '\1',/p" \
# /usr/avr/include/avr/iom32u4.h | sed 's;, */\*\(.*\) \*/.*;,  #\1;'
VECTORS = {
    0: 'reset_vect',  # Reset vector, also used at boot time
    1: 'INT0_vect',  # External Interrupt Request 0
    2: 'INT1_vect',  # External Interrupt Request 1
    3: 'INT2_vect',  # External Interrupt Request 2
    4: 'INT3_vect',  # External Interrupt Request 3
    7: 'INT6_vect',  # External Interrupt Request 6
    9: 'PCINT0_vect',  # Pin Change Interrupt Request 0
    10: 'USB_GEN_vect',  # USB General Interrupt Request
    11: 'USB_COM_vect',  # USB Endpoint/Pipe Interrupt Communication Request
    12: 'WDT_vect',  # Watchdog Time-out Interrupt
    16: 'TIMER1_CAPT_vect',  # Timer/Counter1 Capture Event
    17: 'TIMER1_COMPA_vect',  # Timer/Counter1 Compare Match A
    18: 'TIMER1_COMPB_vect',  # Timer/Counter1 Compare Match B
    19: 'TIMER1_COMPC_vect',  # Timer/Counter1 Compare Match C
    20: 'TIMER1_OVF_vect',  # Timer/Counter1 Overflow
    21: 'TIMER0_COMPA_vect',  # Timer/Counter0 Compare Match A
    22: 'TIMER0_COMPB_vect',  # Timer/Counter0 Compare Match B
    23: 'TIMER0_OVF_vect',  # Timer/Counter0 Overflow
    24: 'SPI_STC_vect',  # SPI Serial Transfer Complete
    25: 'USART1_RX_vect',  # USART1, Rx Complete
    26: 'USART1_UDRE_vect',  # USART1 Data register Empty
    27: 'USART1_TX_vect',  # USART1, Tx Complete
    28: 'ANALOG_COMP_vect',  # Analog Comparator
    29: 'ADC_vect',  # ADC Conversion Complete
    30: 'EE_READY_vect',  # EEPROM Ready
    31: 'TIMER3_CAPT_vect',  # Timer/Counter3 Capture Event
    32: 'TIMER3_COMPA_vect',  # Timer/Counter3 Compare Match A
    33: 'TIMER3_COMPB_vect',  # Timer/Counter3 Compare Match B
    34: 'TIMER3_COMPC_vect',  # Timer/Counter3 Compare Match C
    35: 'TIMER3_OVF_vect',  # Timer/Counter3 Overflow
    36: 'TWI_vect',  # 2-wire Serial Interface
    37: 'SPM_READY_vect',  # Store Program Memory Read
    38: 'TIMER4_COMPA_vect',  # Timer/Counter4 Compare Match A
    39: 'TIMER4_COMPB_vect',  # Timer/Counter4 Compare Match B
    40: 'TIMER4_COMPD_vect',  # Timer/Counter4 Compare Match D
    41: 'TIMER4_OVF_vect',  # Timer/Counter4 Overflow
    42: 'TIMER4_FPF_vect',  # Timer/Counter4 Fault Protection Interrupt
}


class ATmega32U4Meta(AVR8Meta):
    """Specific meta-information to decode an ATmega32U4 firmware"""

    def __init__(self, fwmem, labels):
        super(ATmega32U4Meta, self).__init__(fwmem, labels)
        self.add_cpu_data(PORTS, SRAM_REGS, VECTORS)
