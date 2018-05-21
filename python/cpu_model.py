#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2018 Nicolas Iooss
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
"""Find the CPU model of the current processor

CPU Microcode repository: https://github.com/platomav/CPUMicrocodes
"""
import argparse
import ctypes
import ctypes.util
import logging
import os.path
import platform
import re
import struct
import sys


logger = logging.getLogger(__name__)


# Database of "model, stepping: accronym, product name, public names" from:
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/intel-family.h
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/power/x86/turbostat/turbostat.c
# https://newsroom.intel.com/wp-content/uploads/sites/11/2018/01/microcode-update-guidance.pdf
# https://newsroom.intel.com/wp-content/uploads/sites/11/2018/02/microcode-update-guidance.pdf
# https://newsroom.intel.com/wp-content/uploads/sites/11/2018/04/microcode-update-guidance.pdf
# https://en.wikipedia.org/wiki/Intel_Core
# http://users.atw.hu/instlatx64/
INTEL_FAM6_MODELS = {
    (0x01, 1): (None, '?'),
    (0x01, 2): (None, '?'),
    (0x01, 6): (None, '?'),
    (0x01, 7): (None, '?', (
        '2x Intel® Pentium® Pro, 200 MHz (3 x 67) (P6) (32 bits)',
    )),
    (0x01, 9): (None, '?', (
        '2x Intel® Pentium® Pro, 200 MHz (3 x 67) (32 bits)',
    )),
    (0x03, 0): (None, '?'),
    (0x03, 2): (None, '?', (
        'Intel® PII overdrive (32 bits)',
    )),
    (0x03, 3): (None, '?', (
        'Intel® PII (Klamath) (32 bits)',
    )),
    (0x03, 4): (None, '?'),
    (0x05, 1): (None, '?', (
        'Intel® Celeron®, 266 MHz (4 x 67) (Covington) (32 bits)',
        '2x Intel® Pentium® II, 333 MHz (5 x 67) (Deschutes) (32 bits)',
    )),
    (0x05, 0): (None, '?'),
    (0x05, 2): (None, '?'),
    (0x05, 3): (None, '?', (
        'Intel® PII (Deschutes) (32 bits)',
    )),
    (0x06, 0): (None, '?', (
        'Intel® Celeron®-A, 300 MHz (4.5 x 67) (Mendocino) (32 bits)',
    )),
    (0x06, 5): (None, '?', (
        'Intel® PII Celeron (Mendocino) (32 bits)',
    )),
    (0x06, 10): (None, '?', (
        'Intel® PII Celeron (Dixon) (32 bits)',
    )),
    (0x06, 13): (None, '?'),
    (0x07, 0): (None, '?'),
    (0x07, 1): (None, '?'),
    (0x07, 2): (None, '?'),
    (0x07, 3): (None, '?', (
        '2x Intel® Pentium® III, 500 MHz (5 x 100) (Katmai) (32 bits)',
        'Intel® Pentium® III, 450 MHz (4.5 x 100) (Katmai) (32 bits)',
        '8x Intel® Pentium® III Xeon, 550 MHz (5.5 x 100) (Tanner) (32 bits)',
    )),
    (0x08, 0): (None, '?'),
    (0x08, 1): (None, '?'),
    (0x08, 3): (None, '?', (
        '2x Intel® Pentium® IIIE, 733 MHz (5.5 x 133) (32 bits)',
    )),
    (0x08, 6): (None, '?', (
        'Intel® Celeron®, 700 MHz (10.5 x 67) (Coppermine-128) (32 bits)',
    )),
    (0x08, 10): (None, '?'),
    (0x09, 0): (None, '?'),
    (0x09, 1): (None, '?'),
    (0x09, 2): (None, '?'),
    (0x09, 4): (None, '?'),
    (0x09, 6): (None, '?'),
    (0x09, 5): (None, '?', (
        'Mobile Intel® Celeron® M 320, 1300 MHz (13 x 100) (Banias-512) (32 bits)',
        'Mobile Intel Shelton, 600 MHz (6 x 100) (Banias-0, 0MB L2) (32 bits)',
    )),
    (0x0a, 0): (None, '?'),
    (0x0a, 1): (None, '?'),
    (0x0a, 4): (None, '?'),
    (0x0b, 0): (None, '?'),
    (0x0b, 1): (None, '?', (
        '2x Intel® Pentium® III-S, 1266 MHz (9.5 x 133) (Tualatin, A80530) (32 bits)',
    )),
    (0x0b, 4): (None, '?'),
    (0x0d, 0): (None, '?'),
    (0x0d, 1): (None, '?'),
    (0x0d, 2): (None, '?'),
    (0x0d, 6): (None, '?'),
    (0x0d, 8): (None, '?', (
        'Mobile Intel® Pentium® M 730, 1600 MHz (12 x 133) (Dothan) (32 bits)',
    )),
    (0x0e, 0): (None, '?'),
    (0x0e, 1): (None, '?'),
    (0x0e, 4): (None, 'Core Yonah', (
        'Mobile DualCore Intel® Core™ Duo T2500, 2000 MHz (12 x 167) (Yonah) (32 bits)',
    )),
    (0x0e, 8): (None, 'Core Yonah', (
        'Mobile Intel® Celeron® 215, 1333 MHz (10 x 133) (Yonah-512) (32 bits)',
    )),
    (0x0e, 12): (None, '?'),
    (0x0f, 0): (None, '?'),
    (0x0f, 1): (None, '?'),
    (0x0f, 2): (None, 'Core 2 Merom', (
        'DualCore Intel® Core™ 2 Duo E6300, 1866 MHz (7 x 267) (Conroe-2M)',
    )),
    (0x0f, 4): (None, '?', (
        'DualCore Intel® Core™ 2 Duo E6700, 2666 MHz (10 x 267) (Conroe)',
        '2x DualCore Intel® Xeon® 5140, 2333 MHz (7 x 333) (Woodcrest)',
    )),
    (0x0f, 5): (None, '?'),
    (0x0f, 6): (None, 'Core 2 Merom', (
        'Mobile DualCore Intel® Core™ 2 Duo T5600, 1833 MHz (11 x 167) (Merom-2M)',
    )),
    (0x0f, 7): (None, '?', (
        '2x QuadCore Intel® Xeon® L5320, 1866 MHz (7 x 267) (Clovertown)',
        'QuadCore Intel® Xeon® X3210, 2133 MHz (8 x 267) (Kentsfield)',
        'QuadCore Intel® Core™ 2 Extreme QX6700, 2666 MHz (10 x 267) (Kentsfield)',
    )),
    (0x0f, 9): (None, '?', (
        '2x QuadCore Intel® Core™ 2 Quad Q6400, 2133 MHz (8 x 267) (Tigerton)',
    )),
    (0x0f, 10): (None, '?'),
    (0x0f, 11): (None, '?', (
        'DualCore Intel® Core™ 2 Duo E6750, 2666 MHz (8 x 333) (Conroe)',
        'Intel(R) Core(TM)2 Duo CPU     E6550  @ 2.33GHz',
    )),
    (0x0f, 13): (None, '?'),
    (0x15, 0): (None, '?', (
        'Intel® LE80578, 800 MHz (16 x 50) (Vermilion)',
    )),
    (0x16, 0): (None, '?'),
    (0x16, 1): (None, 'Core 2 Merom L', (
        'Intel® Celeron® 420, 1600 MHz (8 x 200) (Conroe-L)',
        'Intel(R) Celeron(R) CPU          220  @ 1.20GHz',
    )),
    (0x17, 0): (None, '?'),
    (0x17, 1): (None, '?'),
    (0x17, 4): (None, '?'),
    (0x17, 6): (None, 'Core 2 Penryn, Harpertown, Wolfdale C0, M0, Wolfdale Xeon C0', (
        '2x QuadCore Intel® Xeon® E5462, 2800 MHz (7 x 400) (Harpertown)',
        'Mobile DualCore Intel® Core™ 2 Duo P8400, 2400 MHz (9 x 267) (Penryn-3M)',
        'QuadCore Intel® Core™ 2 Extreme QX9650, 3000 MHz (9 x 333) (Yorkfield)',
        'Intel® Xeon® Processor X33xx',
        'Intel® Xeon® Processor L5408, L5410, L5420',
        'Intel® Xeon® Processor E5405,E5410,E5420,E5430, E5440, E5450, E5462, E5472',
        'Intel® Xeon® Processor X5450, X5460, X5470, X5472, X5482',
        'Intel® Core™ 2 Duo Processor E7200, E7300, E8190, E8200, E8300, E8400, E8500',
        'Intel® Xeon® Processor E3110, E5205, E5220, L5240, X5260, X5272',
    )),
    (0x17, 7): (None, 'Core 2 Penryn, Yorkfield, Yorkfield Xeon', (
        'Intel® Core™ 2 Quad Q9300 (Yorkfield)',
        'Intel® Core™2 Extreme Processor QX9650, QX9770, QX9775',
        'Intel® Core™2 Quad Processor Q8200, Q8200S, Q8400, Q8400S, Q9300, Q9400, Q9400S, Q9450, Q9500, Q9505, Q9505S, Q9550, Q9550S, Q9650',
        'Intel® Xeon® Processor L3360, X3320, X3330, X3350, X3360, X3370, X3380',
    )),
    (0x17, 10): (None, 'Core 2 Penryn, Harpertown, Wolfdale DP, Wolfdale E0, R0, Wolfdale Xeon E0', (
        'Pentium Dual-Core CPU T4200, 2000MHz (Penryn) (CPUID level 0xD, SSE4.1 disabled)',
        'Intel® Core™ 2 processor, Intel® Pentium® Processor E',
        'Intel® Xeon® Processor L5408, L5410, L5420, L5430',
        'Intel® Xeon® Processor E5405,E5410,E5420,E5430, E5440, E5450, E5462, E5472',
        'Intel® Xeon® Processor X5450, X5460, X5470, X5492',
        'Intel® Core™2 Extreme Processor X9000, X9100',
        'Intel® Core™2 Quad Processor Q9000, Q9100',
        'Intel® Core™ 2 Duo Processor E7400, E7500, E8400, E8500, E8600',
        'Intel® Pentium® Processor E5200, E5300, E5400, E5500, E5700, E5800, E6300, E6500, E6500K, E6600, E6700, E6800',
        'Intel® Celeron® Processor E3200, E3300, E3400, E3500',
        'Intel® Xeon® Processor E3110, E3120, E5205, E5220, L3110, L5215, L5240, X5260, X5270, X5272',
    )),
    (0x1a, 1): (None, 'Nehalem EP', (
        'Intel Nehalem ES (bad L1D data, 4 way instead of 8 way in CPUID level 00000004)',
    )),
    (0x1a, 2): (None, 'Nehalem EP', (
        'QuadCore Intel® Xeon® X5550, 2666 MHz (20 x 133) (Nehalem-EP, Gainestown)',
        '2x QuadCore Intel® Xeon® X5550, 2666 MHz (20 x 133) (Nehalem-EP, Gainestown)',
        '2x DualCore Intel® Xeon® E5502, 1866 MHz (14 x 133) (Nehalem-EP, Gainestown)',
    )),
    (0x1a, 4): (None, 'Nehalem EP, Bloomfield', (
        'QuadCore Intel® Core™ i7 Extreme 965, 3333 MHz (25 x 133) (Bloomfield)',
        'Intel® Core™ i7-965/975 Extreme Processor',
        'Intel® Core™ Processor i7-920, 930, 950, 960',
    )),
    (0x1a, 5): (None, 'Bloomfield, Nehalem EP, Nehalem WS', (
        'Intel® Core™ Processor Extreme Edition i7-965',
        'Intel® Core™ Processor i7-920, 940',
        'Intel® Xeon® Processor W3520, W3530, W3540, W3550, W3565, W3570, W3580',
        'Intel® Xeon® Processor E5502, E5503, E5504, E5506, E5507, E5520, E5530, E5540',
        'Intel® Xeon® Processor L5506, L5508, L5518, L5520, L5530',
        'Intel® Xeon® Processor W5580, W5590',
        'Intel® Xeon® Processor X5550, X5560, X5570',
    )),
    (0x1c, 2): (None, 'Atom Pineview', (
        'Intel® Atom® 230, 1600 MHz (12 x 133) (Diamondville-SC, Bonnell core)',
        'DualCore Intel® Atom® (Silverthorne, Bonnell core)',
        'DualCore Intel® Atom® 330, 1600 MHz (12 x 133) (Diamondville-DC, Bonnell core)',
    )),
    (0x1c, 1): (None, '?'),
    (0x1c, 9): (None, '?'),
    (0x1c, 10): (None, 'Atom Pineview', (
        'DualCore Intel® Atom® D525, 1800 MHz (9 x 200) (Pineview-D, Bonnell core)',
    )),
    (0x1d, 0): (None, 'Core 2 Dunnington', (
        '4x HexaCore Intel® Xeon® ES',
    )),
    (0x1d, 1): (None, 'Core 2 Dunnington', (
        '4x HexaCore Intel® Xeon® MP E7450 (Dunnington-6C)',
    )),
    (0x1e, 0): (None, 'Nehalem', (
        'QuadCore Lynnfield ES (Core i5)',
    )),
    (0x1e, 4): (None, 'Nehalem, Jasper (embedded Nehalem)', (
        'Intel® Xeon® C5500 (Jasper Forest)',
        'Intel® Celeron® Processor P1053',
        'Intel® Xeon® Processor ECxxxx, LCxxxx',
    )),
    (0x1e, 5): (None, 'Clarksfield, Lynnfield, Lynnfield Xeon', (
        'QuadCore Intel® Core™ i7 860, 3366 MHz (25 x 135) (Lynnfield)',
        'Intel® Core™ Q820 (Clarksfield)',
        'Intel® Core™ i7 Q720 (Lynnfield, 6MB L3)',
        'Intel® Core™ i7-7xxQM, i7-8xxQM Processor',
        'Intel® Core™ i7-9xxXM Extreme Processor',
        'Intel® Core™ i5-7xx, i5-7xxS',
        'Intel® Core™ i7-8xx, i7-8xxS, i7-8xxK',
        'Intel® Core™ Extreme Processor i7-920XM, 940XM',
        'Intel® Core™ Processor i7-720QM, 740QM, 820QM, 840QM',
        'Intel® Core™ Processor i7-860, 860S, 870, 870S, 875K, 880',
        'Intel® Core™ Processor i5-750, 750S, 760',
        'Intel® Xeon® Processor L3426',
        'Intel® Xeon® Processor X3430, X3440, X3450, X3460, X3470, X3480',
    )),
    (0x1f, 1): (None, 'Nehalem G (Auburndale / Havendale)', (
        'Havendale, Auburndale (Core i3, cancelled)',
    )),
    (0x25, 2): (None, 'Westmere Client (Clarkdale, Arrandale, Clarkdale Xeon)', (
        'DualCore Intel® Core™ i5 650, 3600 MHz (26 x 138) (Clarkdale)',
        'Intel® Xeon® Processor L3406',
        'Intel® Core™ Processor i7-i7-620M/LM/UM, i7-640LM/UM',
        'Intel® Core™ Processor i5-430M, i5-520M/UM, i5-540M',
        'Intel® Core™ Processor 330M, 350M',
        'Intel® Celeron® Processor P4500, P4505',
        'Intel® Core™ Processor i5-650, 660, 661, 670',
        'Intel® Core™ Processor i3-530, 540, 550, 560',
        'Intel® Pentium® Processor G6950',
    )),
    (0x25, 5): (None, 'Arrandale, Clarkdale', (
        'Intel® Celeron® Mobile P4xxx, U3xxx Processor',
        'Intel® Pentium® Mobile P6xxx, U5xxx Processor',
        'Intel® Core™ i3-3xxE, i3-3xxM, i3-3xxUM Processor',
        'Intel® Core™ i5-4xxM/UM, i5-5xxE/M/UM Processor',
        'Intel® Core™ i7-6xxE/LE/UE/M/LM/UM Processor',
        'Intel® Core™ Processor i7-610E, 620LE/LM/M/UE/UM, 640LM/M/UM, 660LM/UE/UM, 680UM',
        'Intel® Core™ Processor i5-430M/UM, 450M, 460M, 470UM, 480M, 520E/M/UM, 540M/UM, 560M/UM, 580M',
        'Intel® Core™ Processor i3-330E/M/UM, 350M, 370M, 380M/UM, 390M',
        'Intel® Pentium® Processor P6000, P6100, P6200, P6300',
        'Intel® Pentium® Processor U5400, U5600',
        'Intel® Celeron® Processor P4500, P4505, P4600',
        'Intel® Celeron® Processor U3400, U3405, U3600',
        'Intel® Core™ Processor i5-650, 655K, 660, 661, 670, 680',
        'Intel® Core™ Processor i3-530, 540',
        'Intel® Pentium® Processor G6950, G6951, G6960',
    )),
    (0x26, 1): (None, 'Atom Lincroft', (
        'Intel® Atom® Z670 (Tunnel Creek)',
    )),
    (0x27, 2): (None, 'Atom Penwell', (
        'Intel® Atom® Z2460 1.6GHz (Medfield platform, Penwell SoC, Saltwell core)',
    )),
    (0x2a, 2): ('SNB', 'Sandy Bridge', (
        'Sandy Bridge ES',
    )),
    (0x2a, 0): (None, '?'),
    (0x2a, 1): (None, '?'),
    (0x2a, 3): (None, '?'),
    (0x2a, 4): (None, '?'),
    (0x2a, 5): (None, '?'),
    (0x2a, 6): ('SNB', 'Sandy Bridge', (
        'QuadCore Intel® Core™ i7-2600K, 3400 MHz (Sandy Bridge)',
    )),
    (0x2a, 7): ('SNB', 'Sandy Bridge', (
        'Intel® Core™ i3-21xx/23xx-T/M/E/UE Processor',
        'Intel® Core™ i5-23xx/24xx/25xx-T/S/M/K Processor',
        'Intel® Core™ i7-2xxx-S/K/M/QM/LE/UE/QE Processor',
        'Intel® Core™ i7-29xxXM Extreme Processor',
        'Intel® Celeron® Desktop G4xx, G5xx Processor',
        'Intel® Celeron® Mobile 8xx, B8xx Processor',
        'Intel® Pentium® Desktop 350, G6xx, G6xxT, G8xx Processor',
        'Intel® Pentium® Mobile 9xx, B9xx Processor',
        'Intel® Xeon® Processor E3-1200 Product Family',
        'QuadCore Intel® Core™ i5 2400, 3100 MHz (31 x 100) (Sandy Bridge)',
        'QuadCore Intel® Core™ i7 2600, 3400 MHz (34 x 100) (Sandy Bridge)',
        'QuadCore Intel® Core™ i7 2600, 3400 MHz (34 x 100) (Sandy Bridge) with AVX instructions',
        'DuadCore Intel® Pentium® G840 (Sandy Bridge, 3MB L3, no AVX)',
    )),
    (0x2c, 1): (None, 'Westmere EP (Gulftown)', (
        '2x QuadCore Intel® Xeon® X5667, 3066 MHz (23 x 133) (Gulftown)',
    )),
    (0x2c, 2): (None, 'Westmere EP (Gulftown), Westmere EP, WS', (
        'Intel® Core™ i7-970, 980',
        'Intel® Core™ Processor Extreme Edition i7-980X, 990X',
        'Intel® Xeon® Processor W3690',
        'HexaCore Intel® Core™ i7 Extreme 990X, 3466 MHz (26 x 133) (Gulftown)',
        'Intel(R) Xeon(R) CPU           E5620  @ 2.40GHz',
        'Intel® Xeon® Processor E5603, E5606, E5607, E5620, E5630, E5640, E5645, E5649',
        'Intel® Xeon® Processor L5609, L5618, L5630, L5638, L5640',
        'Intel® Xeon® Processor W3670, W3680',
        'Intel® Xeon® Processor X5647, X5650, X5660, X5667, X5670, X5672, X5675, X5677, X5680, X5687, X5690, X5698',
    )),
    (0x2d, 5): ('SNBX', 'Sandy Bridge Xeon (Sandy Bridge E, EN, EP, EP4S)', (
        '2x OctalCore Intel® Xeon®, 3000 MHz (30 x 100) (Sandy Bridge-EP)',
    )),
    (0x2d, 6): ('SNBX', 'Sandy Bridge Xeon (Sandy Bridge E, EN, EP, EP4S)', (
        'Intel® Xeon® Processor E5 Product Family',
        'Intel® Xeon® Processor E5-2620, E5-2630, E5-2630L, E5-2640, E5-2650, E5-2650L, E5-2660, E5-2667, E5-2670, E5-2680, E5-2690',
        'Intel® Pentium® Processor 1405',
        'HexaCore Intel® Core™ i7-3960X Extreme Edition, 3600 MHz (36 x 100) (Sandy Bridge-E)',
    )),
    (0x2d, 7): ('SNBX', 'Sandy Bridge Xeon (Sandy Bridge E, EN, EP, EP4S)', (
        'Intel® Xeon® Processor E5 Product Family',
        'Intel® Pentium® Processor 1405',
        'Intel(R) Xeon(R) CPU E5-2420 0 @ 1.90GHz',
    )),
    (0x2e, 4): (None, 'Nehalem-EX Xeon (Beckton)', (
        '4x HexaCore Intel® Xeon® (Beckton, 48 threads)',
    )),
    (0x2e, 5): (None, 'Nehalem-EX Xeon (Beckton)', (
        '4x QuadCore Intel® Xeon® E7520 (Beckton)',
    )),
    (0x2e, 6): (None, 'Nehalem-EX Xeon (Beckton)', (
        '4x OctaCore Intel® Xeon® X7560 (Beckton)',
        'Intel® Xeon® 65xx, Intel® Xeon® 75xx',
        'Intel® Xeon® Processor E6510, E6540, E7520, E7530, E7540, L7545, L7555, X6550, X7542, X7550, X7560',
    )),
    (0x2f, 0): (None, '?'),
    (0x2f, 1): (None, '?'),
    (0x2f, 2): (None, 'Westmere-EX Xeon (Eagleton), Westmere EX (EGL, WSM)', (
        '4x 10-Core Intel® Xeon® MP E7-4870, 2400 MHz (18 x 133) (Eagleton, Westmere-EX)',
        'Intel® Xeon® Processor E7-2803, 2820, 2830, 2850, 2860, 2870, 4807, 4820, 4830, 4850, 4860, 4870, 8830, 8837, 8850, 8860, 8867L, 8870',
    )),
    (0x35, 0): (None, '?'),
    (0x35, 1): (None, 'Atom Cloverview', (
        'DualCore Intel® Atom® Z2760, 1800MHz (Cloverview, Saltwell core)',
    )),
    (0x36, 0): (None, '?'),
    (0x36, 1): (None, 'Atom Cedarview', (
        'DualCore Intel® Atom® D2700, 2133 MHz (16 x 133) (Cedarview, Saltwell core) Bonnell vs. Saltwell',
        'DualCore Intel® Atom® D2500, 1866 MHz (14 x 133) (Cedarview)',
    )),
    (0x36, 9): (None, 'Atom Cedarview', (
        'Intel® Atom® S1260 @ 2.00GHz (Centerton, Saltwell core)',
    )),
    (0x37, 1): (None, '?'),
    (0x37, 2): (None, '?'),
    (0x37, 3): ('BYT', 'Atom Silvermont (BayTrail/BYT / Valleyview), Valleyview, Bay Trail I (B2, B3 step)', (
        'Intel® Atom® CPU Z3740 @ 1.33GHz (Bay Trail, Silvermont core)',
        'DualCore Intel® Celeron® N2820, 2133 MHz (16 x 133) (Bay Trail-M)',
        'QuadCore Intel® Celeron® J1900, 2000 MHz (24 x 83) (Bay Trail-D)',
        'Intel® Atom® Processor E3800 Product Family',
        'Intel® Celeron® Processor Jxxxx & Nxxxx',
        'Intel® Pentium® Processor Jxxxx & Nxxxx',
        'Intel® Atom® Processor Z3600 & Z3700 Series',
    )),
    (0x37, 8): ('BYT', 'Atom Silvermont (BayTrail/BYT / Valleyview), Valleyview, Bay Trail M/D (C0 step)', (
        'Intel® Atom® CPU Z3745 @ 1.33GHz (Bay Trail-T, Silvermont core)',
        'Intel® Celeron® Processor Jxxxx & Nxxxx',
        'Intel® Pentium® Processor Jxxxx & Nxxxx',
        'Intel® Atom® Processor Z3600 & Z3700 Series',
    )),
    (0x37, 9): (None, 'Valleyview, Bay Trail I (D0, D1 step) ; Valleyview, Bay Trail M/D (D1 step)', (
        'Intel® Atom® Processor E3800 Product Family',
        'Intel® Celeron® Processor N2807, N2930',
        'Intel® Pentium® Processor J1800, J1900',
    )),
    (0x3a, 0): (None, '?'),
    (0x3a, 2): (None, '?'),
    (0x3a, 4): (None, '?'),
    (0x3a, 5): (None, '?'),
    (0x3a, 6): (None, '?'),
    (0x3a, 8): (None, '?'),
    (0x3a, 9): ('IVB', 'Ivy Bridge, Ivy Bridge Xeon E3, Gladden', (
        '3rd Generation Intel® Core™ Mobile Processor Family',
        'Intel® Pentium® Mobile Processor Family',
        'Intel® Celeron® Mobile Processor Family',
        'Intel® Xeon® Processor E3-1200 v2 Product Family',
        'QuadCore Intel® Xeon® E3-1230 v2, 3700 MHz (36 x 103) (Ivy Bridge-WS)',
        'Intel® Celeron® CPU G1610 (no AVX, AESNI, F16C, RDRAND, HTT)',
        'QuadCore Intel® Core™ i7-3770K, 3700 MHz (37 x 100) (Ivy Bridge)',
        'Intel(R) Xeon(R) CPU E3-1230 V2 @ 3.30GHz',
        'Intel® Core™ Processor i3-2115C, i3-3115C',
        'Intel® Pentium® Processor B915C, B925C',
        'Intel® Celeron® Processor 725C',
        'Intel® Xeon® Processor E3-1105C, E3-1125C, E3-1105C v2, E3-1125C v2',
        'Intel® Core™ Processor Extreme Edition i7-4960X',
        'Intel® Core™ Processor i7-4820K, i7-4930K'
    )),
    (0x3c, 3): ('HSW', 'Haswell Core, Haswell Xeon E3', (
        '4th Generation Intel® Core™ Mobile Processor Family',
        'Intel® Pentium® Mobile Processor Family',
        'Intel® Celeron® Mobile Processor Family',
        'Intel® Xeon® Processor E3-1200 v3 Product Family',
        'Intel® Xeon® Processor E3-1220V3, E3-1225V3, E3-1230LV3, E3-1230V3, E3-1240V3, E3-1245V3, E3-1270V3, E3-1275LV3, E3-1275V3, E3-1280V3, E3-1285LV3, E3-1285LV3, E3-1285V3',
        'QuadCore Intel® Core™ i7-4770, 3400 MHz (34 x 100) (Haswell-DT)',
        'QuadCore Intel® Xeon® E3-1245 v3, 3400 MHz (34 x 100) (Haswell)',
        'Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz'
    )),
    (0x3d, 4): ('BDW', 'Broadwell Core (Broadwell U/Y)', (
        '5th Generation Intel® Core™ Processor Family',
        'Intel® Pentium® Mobile Processor Family',
        'Intel® Celeron® Mobile Processor Family',
        'DualCore Intel® Core™ M-5Y70, 2600 MHz (26 x 100) (Broadwell) Haswell vs. Broadwell',
        'Mobile DualCore Intel® Core™ i7-5500U (Broadwell-ULT)',
        'Mobile DualCore Intel® Core™ i5-5250U, 1600 MHz (16 x 100) (Broadwell-U)',
        'Intel® Core™ Processor i7-5650U,i7-5600U, i7-5557U, i7-5550U, i7-5500U',
        'Intel® Core™ Processor i5-5350U, i5-5350,i5-5300U, i5-5287U,i5-5257U, i5-5250U, i5-5200U',
        'Intel® Core™ Processor i3-5157U, i3-5020U, i3-5015U, i3-5010U, i3-5006U, i3-5005U, i3-5010U, i5-5350U, i7-5650U',
        'Intel® Core™ Processor M-5Y71, M-5Y70, M-5Y51, M-5Y3, M-5Y10c, M -5Y10a, M-5Y10',
        'Intel® Pentium® Processor 3805U, 3825U, 3765U, 3755U, 3215U, 3205U',
        'Intel® Celeron® 3765U',
    )),
    (0x3e, 0): (None, '?'),
    (0x3e, 2): (None, '?'),
    (0x3e, 3): ('IVBX', 'Ivy Bridge Xeon (Ivy Bridge EN, EP)', (
        '2x 12-Core Genuine Intel® CPU @ 2.40GHz ES (Ivy Bridge-EP, Ivytown, 30MB L3)',
    )),
    (0x3e, 4): ('IVBX', 'Ivy Bridge Xeon (Ivy Bridge EN, EP), Ivy Bridge Server E, EN, EP, EP4S', (
        'Intel® Xeon® Processor E5v2 Product Family',
        'Intel® Xeon® CPU E5-2697 v2 @ 2.70GHz (Ivy Bridge-EP, Ivytown, 30MB L3)',
        'HexaCore Intel® Core™ i7-4930K, 3400 MHz (34 x 100) (Ivy Bridge-E, Ivytown, 30MB L3)',
        'Intel(R) Xeon(R) CPU @ 2.50GHz',
        'Intel® Xeon® Processor v2 E5-1428L, E5-1620, E5-1650, E5-1660, E5-2403, E5-2407, E5-2418L, E5-2420, E5-2428L, E5-2430, E5-2430L, E5-2440, E5-2448L, E5-2450, E5-2450L, E5-2470, E5-2603, E5-2609, E5-2618L, E5-2620, E5-2628L, E5-2630, E5-2630L, E5-2637, E5-2640, E5-2643, E5-2648L, E5-2650, E5-2650L, E5-2658, E5-2660, E5-2667, E5-2670, E5-2680, E5-2687W, E5-2690, E5-2695, E5-2697, E5-4603, E5-4607, E5-4610, E5-4620, E5-4624L, E5-4627, E5-4640, E5-4650, E5-4657L',
        'Intel® Core™ Processor Extreme Edition i7-4960X',
        'Intel® Core™ Processor i7-4820K, i7-4930K',
    )),
    (0x3e, 6): ('IVBX', 'Ivy Bridge Xeon'),
    (0x3e, 7): ('IVBX', 'Ivy Bridge Xeon (Ivy Bridge Server EX)', (
        'Intel® Xeon® Processor E7v2 Product Family',
    )),
    (0x3f, -1): ('HSX', 'Haswell X (Haswell EP, EN)', (
        'OctalCore Intel® Core™ i7-5960X Extreme Edition, 3300 MHz (33 x 100) (Haswell-E)',
    )),
    (0x3f, 2): ('HSX', 'Haswell X (Haswell EP, EN), Haswell Server E, EP, EP4S', (
        'Intel® Xeon® Processor E5v3 Product Family',
        'HexaCore Intel® Core™ i7-5820K, 3300 MHz (33 x 100) (Haswell-E)',
        '2x 18-Core Intel® Xeon® E5-2699 v3, 2300 MHz (23 x 100) (Haswell-EP)',
        '2x 10-Core Intel® Xeon® E5-2660 v3, 2600 MHz (26 x 100) (Haswell-EP)',
        'Intel(R) Xeon(R) CPU E5-2695 v3 @ 2.30GHz'
    )),
    (0x3f, 4): ('HSX', 'Haswell X (Haswell EX), Haswell Server EX', (
        'Intel® Xeon® Processor E7v3 Product Family',
        'Intel® Xeon® Processor E7-4809V3, E7-4820V3, E7-4830V3, E7-4850V3, E7-8860V3, E7-8867V3, E7-8870V3, E7-8880LV3, E7-8880V3, E7-8890V3, E7-8891V3, E7-8893V3'
    )),
    (0x45, 1): ('HSW', 'Haswell ULT', (
        '4th Generation Intel® Core™ Mobile Processor Family',
        'Intel® Pentium® Mobile Processor Family',
        'Intel® Celeron® Mobile Processor Family',
        'Intel(R) Core(TM) i5-4300U CPU @ 1.90GHz',
        'Intel(R) Core(TM) i7-4500U CPU @ 1.80GHz',
    )),
    (0x46, 1): ('HSW', 'Haswell GT3E (Haswell Perf), Haswell Perf Halo', (
        'Intel® Core™ Extreme Processor (5960x, 5930x, 5820x)',
        'QuadCore Intel® Core™ i7-4770R, 3600 MHz (36 x 100) (Crystal Well-DT, 128MB L4 cache)',
    )),
    (0x47, 1): ('BDW', 'Broadwell GT3E (Broadwell H 43e), Broadwell Xeon E3', (
        '5th Generation Intel® Core™ Mobile Processor Family',
        'Intel® Xeon® Processor E3-1200 v4 Product Family',
        'Intel® Xeon® Processor v4 E3-1258L, E3-1265L, E3-1278L, E3-1285, E3-1285',
        'QuadCore Intel® Core™ i7-5775C, 3300 MHz (33 x 100) (Broadwell-H)',
        'Intel® Core™ Processor i7-5950HQ, i7-5850HQ, i7-5750HQ, i7-5700HQ',
        'Intel® Core™ Processor i5-5575R, i5-5675C, i5-5675R, i7-5775C, i7-5775R',
        'Intel® Core™ Processor i7-5700EQ, i7-5850EQ',
    )),
    (0x4a, -1): (None, 'Atom Merrifield (Tangier)'),
    (0x4a, 8): (None, 'Tangier (SLM)', (
        'Intel® Atom® Processor Z34XX',
    )),
    (0x4a, 9): (None, 'Tangier (SLM)', (
        'Intel® Atom® Processor Z34XX',
    )),
    (0x4c, 1): (None, '?'),
    (0x4c, 2): (None, '?'),
    (0x4c, 3): (None, 'Atom Airmont (CherryTrail / Braswell), Cherry View (Cherry Trail, Braswell)', (
        'QuadCore Intel® Atom® x7-Z8700, 1600MHz (Cherry Trail)',
        'QuadCore Intel® Celeron® N3150, 2083 MHz (26 x 80) (Braswell) Silvermont vs. Airmont',
        'DualCore Intel® Celeron® N3050, 2166 MHz (27 x 80) (Braswell)',
        'Intel® Atom® x5-Zxxxx CPU',
    )),
    (0x4c, 4): (None, 'Cherry View (Cherry Trail, Braswell)', (
        'Intel® Celeron® Processor Jxxxx',
        'Intel® Celeron® Processor N3xxx',
        'Intel® Pentium® Processor J3xxx',
        'Intel® Pentium® Processor N3xxx',
        'Intel® Atom® x5-E8000 Processor',
    )),
    (0x4d, 0): (None, '?'),
    (0x4d, 8): ('AVN', 'Atom Silvermont (Avaton/Rangely)', (
        'OctalCore Intel® Atom® C2750, 2400 MHz (24 x 100) (Avoton)',
        'OctalCore Intel® Atom® C2758, 2400 MHz (24 x 100) (Rangeley)',
        'Intel® Atom® Processor C2000 Product Family',
    )),
    (0x4e, 1): (None, '?'),
    (0x4e, 2): (None, '?'),
    (0x4e, 3): ('SKL', 'Skylake Mobile (Skylake U/Y/U23e)', (
        '6th Generation Intel® Core™ m Processors',
        'DualCore Intel® Core™ i7-6500U, 3100 MHz (31 x 100) (Skylake-U/Y)',
        'DualCore Intel® Core™ m3-6Y30 (Skylake-U/Y)',
    )),
    (0x4e, 8): (None, '?'),
    (0x4f, 0): (None, '?'),
    (0x4f, 1): ('BDX', 'Broadwell X (Broadwell Server E, EP, EP4S, EX)', (
        'Intel® Xeon® Processor E5v4 Product Family',
        'Intel® Xeon® Processor E7v4 Product Family',
        '22-Core Intel® Xeon® E5-2696 v4, 2800 MHz (28 x 100), 55MB L3',
        '2x 18-Core Intel® Xeon® E5-2697 v4, 3600 MHz (36 x 100), 45MB L3/socket',
        'HexaCore Intel® Core™ i7-6800K, 3400 MHz (34 x 100), 15MB L3',
        '10-Core Intel® Core™ i7-6950X Extreme Edition, 4300 MHz (43 x 100), 25MB L3',
        'HexaCore Intel® Core™ i7-6850K, 3800 MHz (38 x 100) (Broadwell-E)',
        'Intel(R) Xeon(R) CPU E5-2623 v4 @ 2.60GHz',
    )),
    (0x55, 3): (None, '?'),
    (0x55, 4): ('SKX', 'Skylake X (Skylake SP, Basin Falls)', (
        'Intel® Core™ i9 79xxX, 78xxX',
        'Intel® Xeon® Scalable Processor Family',
        'Intel® Xeon® Processor W Product Family',
        '18-Core Intel® Xeon® Gold 6154, 3000 MHz (Skylake-E)',
        '2x 16-Core Intel® Xeon® Gold 6130, 2100 MHz (Skylake-E)',
        '2x 18-Core Intel® Xeon® Gold 6154, 3000 MHz (Skylake-E)',
        '2x 28-Core Intel® Xeon® Platinum 8180, 2500 MHz (Skylake-E)',
        '2x HexaCore Intel® Xeon® Bronze 3106 (Skylake-SP) (Skylake-E)',
        '2x OctalCore Intel® Xeon® Silver 4108, 3000 MHz (30 x 100) (Skylake-E)',
        '10-Core Xeon W-2155 (Skylake-W)',
        'HexaCore Intel® Core™ i7-7800X, 3500 MHz (35 x 100) (Skylake-X)',
        '10-Core Intel® Core™ i9-7900X, 4000 MHz (40 x 100) (Skylake-X)',
        '18-Core Intel® Core™ i9-7980XE (Skylake-X)',
        'Intel® Xeon® Bronze Processor 3104, 3106',
        'Intel® Xeon® Gold Processor 5115, 5118, 5119T, 5120, 5120T, 5122, 6126, 6126F, 6126T, 6128, 6130, 6130F, 6130T, 6132, 6134, 6134M, 6136, 6138, 6138F, 6138T, 6140, 6140M, 6142, 6142F, 6142M, 6144, 6146, 6148, 6148F, 6150, 6152, 6154',
        'Intel® Xeon® Platinum Processor 8153, 8156, 8158, 8160, 8160F, 8160M, 8160T, 8164, 8168, 8170, 8170M, 8176, 8176F, 8176M, 8180, 8180M',
        'Intel® Xeon® Silver Processor 4108, 4109T, 4110, 4112, 4114, 4114T, 4116, 4116T',
        'Intel® Xeon® Processor W-2123, W-2125, W-2133, W2135, W-2145, W-2155, W-2195, W-2175',
    )),
    (0x56, 2): ('BDX-DE', 'Broadwell Xeon D (Broadwell DE V1)', (
        'Intel® Xeon® Processor D-1500 Product Family',
        'OctalCore Intel® Xeon® D-1540, 2000 MHz (20 x 100) (Broadwell-DE)',
        'Intel® Xeon® Processor D-1520, D-1540',
    )),
    (0x56, 3): ('BDX-DE', 'Broadwell Xeon D (Broadwell DE V2,V3)', (
        'Intel® Xeon® Processor D-1500 Product Family',
        'Intel® Xeon® Processor D-1518, D-1519, D-1521, D-1527, D-1528, D-1531, D-1533, D-1537, D-1541, D-1548',
        'Intel® Pentium® Processor D1507, D1508, D1509, D1517, D1519',
    )),
    (0x56, 4): ('BDX-DE', 'Broadwell Xeon D (Broadwell DE Y0)', (
        'Intel® Xeon® Processor D-1500 Product Family',
        'Intel® Xeon® Processor D-1557, D-1559, D-1567, D-1571, D-1577, D-1581, D-1587',
    )),
    (0x56, 5): ('BDX-DE', 'Broadwell Xeon D (Broadwell NS, Broadwell DE A1)', (
        'Intel® Xeon® Processor D-1500 NS Product Family',
        'Intel® Xeon® Processor D-1513N, D-1523N, D-1533N, D1543N, D1553N',
    )),
    (0x57, 1): ('PHI KNL', 'Xeon Phi Knights Landing', (
        'Intel® Xeon® Phi™ Processor 72xx',
        '64-Core Intel® Xeon® Phi™ 7210 (Knights Landing, 256 threads)',
        '72-Core Intel® Xeon® Phi™ 7290 (Knights Landing, 288 threads)',
    )),
    (0x5a, 0): (None, 'Atom Moorefield (Anniedale)', (
        'Intel® Atom® 1.0GHz (Moorefield)',
        'Intel® Atom® Processor Z3530, Z3560, Z3570, Z3580, Z3590',
    )),
    (0x5c, 2): (None, 'Broxton', (
        'Intel® Atom® Scalable Platform',
    )),
    (0x5c, 8): (None, '?'),
    (0x5c, 9): ('BXT', 'Atom Goldmont, Apollo Lake', (
        'QuadCore Intel® Pentium® N4200 (Apollo Lake platform, Goldmont core)',
        'QuadCore Intel® Celeron® J3455, 2200 MHz (22 x 100) (Apollo Lake-D)',
        'QuadCore Intel® Celeron® N3450 (Apollo Lake platform, Goldmont core)',
        'Intel® Celeron® & Pentium Processor Product Family',
        'Intel® Pentium® Processor J4205, N4200',
        'Intel® Celeron® Processor J3355, J3455, N3350, N3450',
        'Intel® Atom® Processor x5-E3930, x5-E3940, x7-E3950',
    )),
    (0x5c, 10): (None, 'Apollo Lake', (
        'Intel® Pentium® J4205, N4200',
        'Intel® Celeron® J3355, J3455, N3350, N3450',
        'Intel® Atom® x5-E3930, x5-E3940, x7-E3950',
        'Intel® Atom® A39xx Product Family',
    )),
    (0x5d, 1): (None, '?', (
        'Intel® Atom® x3-C3230 (SoFIA, Smart or Feature phone with Intel Architecture)',
    )),
    (0x5e, 0): (None, '?'),
    (0x5e, 1): (None, '?'),
    (0x5e, 2): (None, '?'),
    (0x5e, 3): ('SKL', 'Skylake Desktop (Skylake H/S, Xeon E3)', (
        '6th Generation Intel® Core™ Processor Family',
        'Intel® Xeon® Processor E3-1200 v5 Product Family',
        'QuadCore Intel® Core™ i5-6400T, 2200 MHz (22 x 100) (Skylake-S) Haswell vs. Broadwell vs. Skylake',
        'QuadCore Intel® Core™ i7-6700K, 4000 MHz (40 x 100) (Skylake-S)',
        'DualCore Intel® Pentium® G4400, 3300 MHz (Skylake)',
        'Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz',
    )),
    (0x5e, 8): (None, '?'),
    (0x5f, 1): ('DNV', 'Atom Denverton (Goldmont Microserver)', (
        '16-Core Intel® Atom® C3958, 2000 MHz (20 x 100) (Denverton)',
        'Intel® Atom® Processor C3000 Product Family',
    )),
    (0x65, 0): (None, 'XGold 7272', (
        'Intel® XMM™ 7272 Modem',
    )),
    (0x66, -1): (None, 'Cannon Lake Mobile'),
    (0x6e, 1): (None, 'Cougar Mountain (AMT)', (
        'Intel® Puma™ 7 Home Gateway',
    )),
    (0x7a, 1): (None, 'Atom Gemini Lake', (
        'Intel® Pentium® Silver processors N5xxx, J5xxx',
        'Intel® Celeron® processors N4xxx, J4xxx',
    )),
    (0x85, 0): ('PHI KNM', 'Xeon Phi Knights Mill', (
        'Intel® Xeon® Phi™ Processor Family',
    )),
    (0x8e, 9): ('KBL', 'Kaby Lake Mobile (Kaby Lake U/Y, U23e)', (
        '7th Generation Intel® Core™ Mobile Processors',
        'DualCore Intel® Core™ i5-7200U, 3100 MHz (31 x 100) (KabyLake-U/Y)',
        'DualCore Intel® Pentium® 4415U 2300 MHz (23 x 100) (Kaby Lake-U)',
        'DualCore Intel® Core™ m3-7Y30, 2600 MHz (26 x 100) (Kaby Lake-Y)',
    )),
    (0x8e, 10): ('KBL', 'Kaby Lake Mobile (Kaby Lake Refresh U4+2), Coffee Lake U43e', (
        '8th Generation Intel® Core™ Mobile Processor Family',
        '8th Generation Intel® Core™ Processor Family',
        'QuadCore Intel® Core™ i5-8250U (Kaby Lake-U Refresh)',
    )),
    (0x9e, 9): ('KBL', 'Kaby Lake Desktop (Kaby Lake H/S/X/G, Xeon E3), Greenlow', (
        '7th Generation Intel® Core™ Processor Family',
        'QuadCore Intel® Core™ i5-7600K, 3800 MHz (Kaby Lake-H/S)',
        'QuadCore Intel® Core™ i7-7700K, 4500 MHz (45 x 100) (Kaby Lake-S)',
        'DualCore Intel® Pentium® G4600 3600 MHz (Kaby Lake-S)',
        'QuadCore Intel® Core™ i7-8705G (Kaby Lake-G)',
        'QuadCore Intel® Core™ i7-7740X 3400 MHz (Kaby Lake-X)',
    )),
    (0x9e, 10): ('KBL', 'Kaby Lake Desktop, Coffee Lake H (6+2), Coffee Lake S (6+2), Coffee Lake S (6+2) Xeon E3', (
        '8th Generation Intel® Core™ Processor Family',
        'HexaCore Intel® Core™ i7-8700K, 4600 MHz (46 x 100) (Coffee Lake-S)',
    )),
    (0x9e, 11): ('KBL', 'Kaby Lake Desktop (Coffee Lake-S), Coffee Lake-S (4+2) + KBL PCH, Coffee Lake-S (4+2) Xeon E3', (
        '8th Generation Intel® Core™ Desktop Processor Family',
        '8th Generation Intel® Core™ Processor Family',
        'QuadCore Intel® Core™ i3-8350K (Coffee Lake-S) (no HTT, TSX, SGX_LC)',
    )),
}
INTEL_FAM15_MODELS = {
    (0x00, -1): (None, '?'),
    (0x01, 1): (None, '?'),
    (0x01, 2): (None, '?'),
    (0x01, 3): (None, '?', (
        'Intel® Celeron®, 1715 MHz (17 x 101) (Willamette-128) (32 bits)',
    )),
    (0x02, 0): (None, '?'),
    (0x02, 1): (None, '?'),
    (0x02, 2): (None, '?'),
    (0x02, 3): (None, '?'),
    (0x02, 4): (None, '?', (
        'Intel® Pentium® 4, 1600 MHz (16 x 100) (Northwood) (32 bits)',
    )),
    (0x02, 5): (None, '?', (
        '2x Intel® Xeon®, 3066 MHz (23 x 133) (Gallatin DP) (32 bits)',
        'Intel® Pentium® 4 Extreme Edition, 3466 MHz (13 x 267) (Gallatin) (32 bits)',
    )),
    (0x02, 6): (None, '?'),
    (0x02, 7): (None, '?', (
        'Intel® Celeron®, 2033 MHz (20 x 102) (Northwood-128) (32 bits)',
        'Intel® Pentium® 4, 2400 MHz (18 x 133) (Northwood) (32 bits)',
    )),
    (0x02, 9): (None, '?', (
        'Intel® Pentium® 4, 2800 MHz (14 x 200) (Northwood HyperThreading) (32 bits)',
        'Intel(R) Xeon(TM) CPU 3.06GHz',
    )),
    (0x03, 0): (None, '?'),
    (0x03, 1): (None, '?'),
    (0x03, 2): (None, '?'),
    (0x03, 3): (None, '?'),
    (0x03, 4): (None, '?', (
        '2x Intel® Xeon® (Nocona) (32 bits)',
        'Intel Pantium 4 (Prescott) (32 bits)',  # Or Pentium? (typo?)
    )),
    (0x03, 6): (None, '?'),
    (0x03, 7): (None, '?'),
    (0x04, 0): (None, '?'),
    (0x04, 2): (None, '?'),
    (0x04, 6): (None, '?'),
    (0x04, 1): (None, '?', (
        'Intel® Celeron® D 326, 2533 MHz (19 x 133) (Prescott-256)',
        '2x Intel P4 Xeon 3.40GHz (Cranford)',
    )),
    (0x04, 3): (None, '?', (
        'Intel® Xeon®, 3200 MHz (16 x 200) (Irwindale)',
        'Intel® Pentium® 4 640, 3200 MHz (16 x 200) (Prescott-2M)',
        'Intel® Pentium® 4 Extreme Edition, 3733 MHz (14 x 267) (Prescott-2M)',
    )),
    (0x04, 4): (None, '?', (
        'DualCore Intel® Pentium® D 820, 2800 MHz (14 x 200) (Smithfield)',
    )),
    (0x04, 7): (None, '?'),
    (0x04, 8): (None, '?', (
        '4x Intel® Xeon® 7020 2667.2 MHz (16.0 x 166.7 MHz) (Paxville)',
    )),
    (0x04, 9): (None, '?'),
    (0x04, 10): (None, '?', (
        '2x Intel® Xeon®, 3400 MHz (17 x 200) (Irwindale)',
    )),
    (0x06, 0): (None, '?'),
    (0x06, 1): (None, '?'),
    (0x06, 2): (None, '?', (
        'DualCore Intel® Pentium® Extreme Edition 955, 3466 MHz (13 x 267) (Presler)',
    )),
    (0x06, 3): (None, '?'),
    (0x06, 4): (None, '?', (
        'Intel® Xeon® 5060 3192 MHz 3066.7MHz (Dempsey)',
    )),
    (0x06, 5): (None, '?', (
        'Intel® Celeron® D 347, 3066 MHz (23 x 133) (Cedar Mill)',
    )),
    (0x06, 6): (None, '?', (
        '2x DualCore Intel® Xeon®, 3000 MHz (18 x 167) (Tulsa)',
    )),
    (0x06, 8): (None, '?', (
        '2x Intel® Xeon® MP 7140M 2792.7 MHz (14.0 x 199.5 MHz) (Tulsa)',
    )),
}
CPU_MODELS = {
    'GenuineIntel': {
        6: INTEL_FAM6_MODELS,
        15: INTEL_FAM15_MODELS,
    },
}


# Latest Intel microcode update, from:
#   bsdtar -Oxf /boot/intel-ucode.img | \
#   iucode_tool -tb -l - | \
#   sed 's/^\s*\S*: sig \(0x[0-9a-f]\+\), pf_mask 0x[0-9a-f]\+, \([0-9-]\+\),
#       rev \(0x[0-9a-f]\+\), size \S\+$/    (\1, \3, '"'"'\2'"'"'),/'
# Official source: https://downloadcenter.intel.com/download/27337/Linux-Processor-Microcode-Data-File?v=t
INTEL_UCODE_VERSIONS = (
    (0x00000611, 0x0b27, '1996-12-18'),
    (0x00000612, 0x00c6, '1996-12-10'),
    (0x00000616, 0x00c6, '1996-12-10'),
    (0x00000617, 0x00c6, '1996-12-10'),
    (0x00000619, 0x00d2, '1998-02-18'),
    (0x00000630, 0x0013, '1996-08-27'),
    (0x00000632, 0x0020, '1996-09-03'),
    (0x00000633, 0x0036, '1998-09-23'),
    (0x00000634, 0x0037, '1998-09-23'),
    (0x00000650, 0x0019, '1997-12-12'),
    (0x00000650, 0x0024, '1998-01-16'),
    (0x00000650, 0x002e, '1998-02-11'),
    (0x00000650, 0x002f, '1998-02-11'),
    (0x00000650, 0x0040, '1999-05-25'),
    (0x00000650, 0x0041, '1999-05-25'),
    (0x00000650, 0x0044, '1999-05-25'),
    (0x00000650, 0x0045, '1999-05-25'),
    (0x00000651, 0x0040, '1999-05-25'),
    (0x00000651, 0x0041, '1999-05-25'),
    (0x00000651, 0x0042, '1999-05-25'),
    (0x00000652, 0x002a, '1999-05-12'),
    (0x00000652, 0x002b, '1999-05-12'),
    (0x00000652, 0x002c, '1999-05-17'),
    (0x00000652, 0x002d, '1999-05-18'),
    (0x00000653, 0x000b, '1999-05-20'),
    (0x00000653, 0x000c, '1999-05-18'),
    (0x00000653, 0x000d, '1999-05-18'),
    (0x00000653, 0x0010, '1999-06-28'),
    (0x00000660, 0x000a, '1999-05-05'),
    (0x00000665, 0x0003, '1999-05-05'),
    (0x0000066a, 0x000b, '1999-05-05'),
    (0x0000066a, 0x000c, '1999-05-05'),
    (0x0000066a, 0x000d, '1999-05-05'),
    (0x0000066d, 0x0005, '1999-03-12'),
    (0x0000066d, 0x0006, '1999-03-12'),
    (0x0000066d, 0x0007, '1999-05-05'),
    (0x00000670, 0x0006, '1998-05-28'),
    (0x00000670, 0x0007, '1998-06-02'),
    (0x00000671, 0x0003, '1998-08-11'),
    (0x00000671, 0x0014, '1998-08-11'),
    (0x00000672, 0x0010, '1999-09-22'),
    (0x00000672, 0x0038, '1999-09-22'),
    (0x00000673, 0x000e, '1999-09-10'),
    (0x00000673, 0x002e, '1999-09-10'),
    (0x00000680, 0x0014, '1999-06-10'),
    (0x00000680, 0x0015, '1999-06-10'),
    (0x00000680, 0x0016, '1999-06-10'),
    (0x00000680, 0x0017, '1999-06-10'),
    (0x00000681, 0x000d, '1999-09-21'),
    (0x00000681, 0x000e, '1999-09-21'),
    (0x00000681, 0x000f, '1999-09-21'),
    (0x00000681, 0x0010, '1999-09-21'),
    (0x00000681, 0x0011, '1999-09-21'),
    (0x00000681, 0x0014, '1999-12-09'),
    (0x00000683, 0x0007, '1999-10-15'),
    (0x00000683, 0x0008, '1999-10-15'),
    (0x00000683, 0x0010, '2001-02-06'),
    (0x00000683, 0x0013, '2001-02-06'),
    (0x00000683, 0x0014, '2001-02-06'),
    (0x00000686, 0x0002, '2000-05-04'),
    (0x00000686, 0x0007, '2000-05-05'),
    (0x00000686, 0x0008, '2000-05-05'),
    (0x00000686, 0x0009, '2000-05-04'),
    (0x00000686, 0x000a, '2000-05-04'),
    (0x00000686, 0x000b, '2000-05-04'),
    (0x00000686, 0x000c, '2000-05-04'),
    (0x0000068a, 0x0001, '2000-11-02'),
    (0x0000068a, 0x0004, '2000-12-07'),
    (0x0000068a, 0x0005, '2000-12-07'),
    (0x00000690, 0x0004, '2000-02-06'),
    (0x00000691, 0x0001, '2002-05-27'),
    (0x00000691, 0x0002, '2000-02-07'),
    (0x00000692, 0x0001, '2002-06-20'),
    (0x00000692, 0x0003, '2000-03-22'),
    (0x00000694, 0x0002, '2002-09-26'),
    (0x00000695, 0x0007, '2004-11-09'),
    (0x00000695, 0x0047, '2004-11-09'),
    (0x00000696, 0x0001, '2000-07-07'),
    (0x000006a0, 0x0003, '2000-01-10'),
    (0x000006a1, 0x0001, '2000-03-06'),
    (0x000006a4, 0x0001, '2000-06-16'),
    (0x000006b0, 0x0004, '2000-11-15'),
    (0x000006b0, 0x0019, '2001-01-29'),
    (0x000006b0, 0x001a, '2001-01-29'),
    (0x000006b1, 0x001c, '2001-02-15'),
    (0x000006b1, 0x001d, '2001-02-20'),
    (0x000006b4, 0x0001, '2002-01-10'),
    (0x000006b4, 0x0002, '2002-01-11'),
    (0x000006d0, 0x0006, '2003-05-22'),
    (0x000006d1, 0x0009, '2003-07-09'),
    (0x000006d2, 0x0010, '2003-08-14'),
    (0x000006d6, 0x0018, '2004-10-17'),
    (0x000006d8, 0x0020, '2004-07-22'),
    (0x000006d8, 0x0021, '2006-08-31'),
    (0x000006e0, 0x0008, '2005-02-15'),
    (0x000006e1, 0x000c, '2005-04-13'),
    (0x000006e4, 0x0026, '2005-08-16'),
    (0x000006e8, 0x0033, '2005-09-25'),
    (0x000006e8, 0x0039, '2005-11-15'),
    (0x000006e8, 0x003c, '2006-02-08'),
    (0x000006ec, 0x0054, '2006-05-01'),
    (0x000006ec, 0x0055, '2006-05-01'),
    (0x000006ec, 0x0056, '2006-06-22'),
    (0x000006ec, 0x0059, '2006-09-12'),
    (0x000006ec, 0x005b, '2007-02-08'),
    (0x000006f0, 0x0005, '2005-08-18'),
    (0x000006f1, 0x0012, '2005-11-29'),
    (0x000006f2, 0x0057, '2007-03-15'),
    (0x000006f2, 0x005a, '2007-09-26'),
    (0x000006f2, 0x005c, '2010-10-02'),
    (0x000006f2, 0x005d, '2010-10-02'),
    (0x000006f4, 0x0028, '2006-04-17'),
    (0x000006f5, 0x0033, '2006-05-01'),
    (0x000006f5, 0x0036, '2006-05-23'),
    (0x000006f5, 0x0038, '2006-07-25'),
    (0x000006f5, 0x0039, '2006-07-27'),
    (0x000006f6, 0x004a, '2006-06-27'),
    (0x000006f6, 0x00c7, '2007-03-15'),
    (0x000006f6, 0x00cb, '2007-09-16'),
    (0x000006f6, 0x00cc, '2007-09-16'),
    (0x000006f6, 0x00cd, '2007-09-16'),
    (0x000006f6, 0x00d0, '2010-09-30'),
    (0x000006f6, 0x00d1, '2010-10-01'),
    (0x000006f6, 0x00d2, '2010-10-01'),
    (0x000006f7, 0x0068, '2007-09-16'),
    (0x000006f7, 0x0069, '2007-09-17'),
    (0x000006f7, 0x006a, '2010-10-02'),
    (0x000006f7, 0x006b, '2010-10-02'),
    (0x000006f9, 0x0082, '2006-09-03'),
    (0x000006f9, 0x0083, '2006-09-28'),
    (0x000006f9, 0x0084, '2006-10-12'),
    (0x000006fa, 0x0092, '2007-03-13'),
    (0x000006fa, 0x0094, '2007-09-24'),
    (0x000006fa, 0x0095, '2010-10-02'),
    (0x000006fb, 0x00b6, '2007-07-13'),
    (0x000006fb, 0x00b7, '2007-08-06'),
    (0x000006fb, 0x00b8, '2009-04-28'),
    (0x000006fb, 0x00b9, '2009-05-11'),
    (0x000006fb, 0x00ba, '2010-10-03'),
    (0x000006fb, 0x00bb, '2010-10-03'),
    (0x000006fb, 0x00bc, '2010-10-03'),
    (0x000006fb, 0x00c1, '2011-10-04'),
    (0x000006fd, 0x00a3, '2007-08-13'),
    (0x000006fd, 0x00a4, '2010-10-02'),
    (0x00000f05, 0x000b, '2000-08-24'),
    (0x00000f05, 0x000c, '2000-08-24'),
    (0x00000f06, 0x0004, '2000-09-11'),
    (0x00000f07, 0x0008, '2000-11-15'),
    (0x00000f07, 0x0012, '2002-07-16'),
    (0x00000f08, 0x0008, '2000-11-01'),
    (0x00000f09, 0x0008, '2001-01-04'),
    (0x00000f0a, 0x0013, '2002-07-16'),
    (0x00000f0a, 0x0014, '2002-07-16'),
    (0x00000f0a, 0x0015, '2002-08-21'),
    (0x00000f11, 0x000a, '2003-07-29'),
    (0x00000f12, 0x002d, '2003-05-02'),
    (0x00000f12, 0x002e, '2003-05-02'),
    (0x00000f12, 0x002f, '2003-05-02'),
    (0x00000f13, 0x0005, '2003-05-08'),
    (0x00000f20, 0x0001, '2001-04-23'),
    (0x00000f21, 0x0001, '2001-05-29'),
    (0x00000f21, 0x0002, '2001-05-29'),
    (0x00000f21, 0x0003, '2001-05-29'),
    (0x00000f22, 0x0005, '2003-07-29'),
    (0x00000f23, 0x0008, '2001-07-30'),
    (0x00000f23, 0x0009, '2001-07-30'),
    (0x00000f23, 0x000d, '2001-08-17'),
    (0x00000f24, 0x001e, '2003-06-05'),
    (0x00000f24, 0x001f, '2003-06-05'),
    (0x00000f24, 0x0020, '2003-06-05'),
    (0x00000f24, 0x0021, '2003-06-10'),
    (0x00000f25, 0x0029, '2004-08-11'),
    (0x00000f25, 0x002a, '2004-08-11'),
    (0x00000f25, 0x002b, '2004-08-11'),
    (0x00000f25, 0x002c, '2004-08-26'),
    (0x00000f26, 0x0010, '2004-08-05'),
    (0x00000f27, 0x0037, '2003-06-04'),
    (0x00000f27, 0x0038, '2003-06-04'),
    (0x00000f27, 0x0039, '2003-06-04'),
    (0x00000f29, 0x002d, '2004-08-11'),
    (0x00000f29, 0x002e, '2004-08-11'),
    (0x00000f29, 0x002f, '2004-08-11'),
    (0x00000f30, 0x000e, '2003-06-24'),
    (0x00000f30, 0x0012, '2003-08-13'),
    (0x00000f30, 0x0013, '2003-08-15'),
    (0x00000f31, 0x0001, '2003-07-25'),
    (0x00000f31, 0x000b, '2003-10-21'),
    (0x00000f32, 0x000a, '2004-05-11'),
    (0x00000f33, 0x000c, '2005-04-21'),
    (0x00000f34, 0x0008, '2004-02-10'),
    (0x00000f34, 0x0012, '2004-06-30'),
    (0x00000f34, 0x0017, '2005-04-21'),
    (0x00000f36, 0x0007, '2004-03-09'),
    (0x00000f37, 0x0002, '2003-12-09'),
    (0x00000f37, 0x0003, '2003-12-18'),
    (0x00000f40, 0x0006, '2004-03-18'),
    (0x00000f41, 0x0016, '2005-04-21'),
    (0x00000f41, 0x0017, '2005-04-22'),
    (0x00000f42, 0x0003, '2005-04-21'),
    (0x00000f43, 0x0005, '2005-04-21'),
    (0x00000f44, 0x0006, '2005-04-21'),
    (0x00000f46, 0x0004, '2005-04-11'),
    (0x00000f47, 0x0003, '2005-04-21'),
    (0x00000f48, 0x0007, '2005-06-30'),
    (0x00000f48, 0x000c, '2006-05-08'),
    (0x00000f48, 0x000e, '2008-01-15'),
    (0x00000f49, 0x0003, '2005-04-21'),
    (0x00000f4a, 0x0002, '2005-06-10'),
    (0x00000f4a, 0x0004, '2005-12-14'),
    (0x00000f60, 0x0005, '2005-01-24'),
    (0x00000f61, 0x0007, '2005-06-10'),
    (0x00000f61, 0x0008, '2005-06-10'),
    (0x00000f62, 0x0005, '2005-07-20'),
    (0x00000f62, 0x000f, '2005-12-15'),
    (0x00000f63, 0x0005, '2005-10-10'),
    (0x00000f64, 0x0002, '2005-12-15'),
    (0x00000f64, 0x0004, '2005-12-23'),
    (0x00000f65, 0x0008, '2006-04-26'),
    (0x00000f65, 0x000b, '2007-05-10'),
    (0x00000f66, 0x001b, '2006-03-10'),
    (0x00000f68, 0x0009, '2006-07-14'),
    (0x00001632, 0x0002, '1998-06-10'),
    (0x00010650, 0x0002, '2005-09-18'),
    (0x00010650, 0x0002, '2006-05-13'),
    (0x00010660, 0x0004, '2006-06-12'),
    (0x00010661, 0x0012, '2006-09-11'),
    (0x00010661, 0x0031, '2007-03-16'),
    (0x00010661, 0x0033, '2007-03-16'),
    (0x00010661, 0x0035, '2007-03-16'),
    (0x00010661, 0x0036, '2007-05-01'),
    (0x00010661, 0x0038, '2007-09-19'),
    (0x00010661, 0x0042, '2010-10-04'),
    (0x00010661, 0x0043, '2010-10-04'),
    (0x00010661, 0x0044, '2010-10-04'),
    (0x00010661, 0x0045, '2010-10-04'),
    (0x00010670, 0x0005, '2007-02-09'),
    (0x00010671, 0x0106, '2007-03-29'),
    (0x00010674, 0x0404, '2007-06-08'),
    (0x00010674, 0x0405, '2007-07-20'),
    (0x00010676, 0x060b, '2008-01-19'),
    (0x00010676, 0x060c, '2008-01-19'),
    (0x00010676, 0x060f, '2010-09-29'),
    (0x00010676, 0x0612, '2015-08-02'),
    (0x00010677, 0x0701, '2007-10-26'),
    (0x00010677, 0x0703, '2008-01-19'),
    (0x00010677, 0x0705, '2008-04-28'),
    (0x00010677, 0x070a, '2010-09-29'),
    (0x00010677, 0x070d, '2015-08-02'),
    (0x0001067a, 0x0a07, '2008-04-09'),
    (0x0001067a, 0x0a0b, '2010-09-28'),
    (0x0001067a, 0x0a0e, '2015-07-29'),
    (0x000106a4, 0x0010, '2009-02-20'),
    (0x000106a4, 0x0011, '2009-04-21'),
    (0x000106a4, 0x0012, '2013-06-21'),
    (0x000106a4, 0x0013, '2015-06-30'),
    (0x000106a5, 0x000f, '2009-02-20'),
    (0x000106a5, 0x0011, '2009-04-14'),
    (0x000106a5, 0x0015, '2010-03-03'),
    (0x000106a5, 0x0019, '2013-06-21'),
    (0x000106a5, 0x001b, '2015-06-27'),
    (0x000106c1, 0x0109, '2007-12-03'),
    (0x000106c2, 0x0211, '2008-10-06'),
    (0x000106c2, 0x0212, '2008-10-06'),
    (0x000106c2, 0x0213, '2008-12-02'),
    (0x000106c2, 0x0217, '2009-04-10'),
    (0x000106c2, 0x0218, '2009-04-10'),
    (0x000106c2, 0x0219, '2009-04-10'),
    (0x000106c9, 0x0007, '2009-02-11'),
    (0x000106c9, 0x0007, '2009-02-13'),
    (0x000106ca, 0x0106, '2009-08-25'),
    (0x000106ca, 0x0107, '2009-08-25'),
    (0x000106d0, 0x0005, '2007-12-04'),
    (0x000106d1, 0x0021, '2008-06-04'),
    (0x000106d1, 0x0026, '2009-04-06'),
    (0x000106d1, 0x0029, '2010-09-30'),
    (0x000106d1, 0x002a, '2015-08-03'),
    (0x000106e4, 0x0002, '2010-03-08'),
    (0x000106e4, 0x0003, '2013-07-01'),
    (0x000106e5, 0x0003, '2009-05-29'),
    (0x000106e5, 0x0004, '2010-04-05'),
    (0x000106e5, 0x0005, '2011-09-01'),
    (0x000106e5, 0x0006, '2013-07-01'),
    (0x000106e5, 0x0007, '2013-08-20'),
    (0x000106e5, 0x0008, '2015-06-30'),
    (0x00020652, 0x0006, '2009-09-15'),
    (0x00020652, 0x0009, '2009-11-12'),
    (0x00020652, 0x000c, '2010-06-10'),
    (0x00020652, 0x000d, '2011-09-01'),
    (0x00020652, 0x000e, '2013-06-26'),
    (0x00020652, 0x000f, '2015-06-30'),
    (0x00020655, 0x0002, '2010-03-01'),
    (0x00020655, 0x0003, '2011-09-01'),
    (0x00020655, 0x0004, '2013-06-28'),
    (0x00020655, 0x0005, '2015-06-30'),
    (0x00020661, 0x0104, '2009-10-23'),
    (0x00020661, 0x0105, '2011-07-18'),
    (0x000206a0, 0x0029, '2009-11-02'),
    (0x000206a1, 0x0007, '2009-12-23'),
    (0x000206a2, 0x0027, '2010-05-02'),
    (0x000206a3, 0x0009, '2010-06-09'),
    (0x000206a4, 0x0022, '2010-04-14'),
    (0x000206a5, 0x0007, '2010-07-22'),
    (0x000206a6, 0x0028, '2010-09-15'),
    (0x000206a7, 0x0017, '2011-04-07'),
    (0x000206a7, 0x001b, '2011-07-14'),
    (0x000206a7, 0x0025, '2011-10-11'),
    (0x000206a7, 0x0028, '2012-04-24'),
    (0x000206a7, 0x0029, '2013-06-12'),
    (0x000206a7, 0x002d, '2018-02-07'),
    (0x000206c1, 0x0006, '2009-12-22'),
    (0x000206c2, 0x000f, '2010-06-18'),
    (0x000206c2, 0x0013, '2010-09-07'),
    (0x000206c2, 0x001d, '2015-08-04'),
    (0x000206d5, 0x0513, '2011-10-13'),
    (0x000206d6, 0x060c, '2011-09-29'),
    (0x000206d6, 0x0618, '2012-04-18'),
    (0x000206d6, 0x0619, '2012-05-22'),
    (0x000206d6, 0x061a, '2013-01-25'),
    (0x000206d6, 0x061c, '2018-01-30'),
    (0x000206d7, 0x070c, '2012-04-03'),
    (0x000206d7, 0x070d, '2012-05-22'),
    (0x000206d7, 0x0710, '2013-06-17'),
    (0x000206d7, 0x0713, '2018-01-26'),
    (0x000206e6, 0x0002, '2009-12-08'),
    (0x000206e6, 0x0007, '2010-04-21'),
    (0x000206e6, 0x000b, '2015-07-24'),
    (0x000206f0, 0x0004, '2010-06-30'),
    (0x000206f1, 0x0008, '2010-10-13'),
    (0x000206f2, 0x0032, '2011-07-21'),
    (0x000206f2, 0x0034, '2011-08-31'),
    (0x000206f2, 0x0036, '2012-04-12'),
    (0x000206f2, 0x0037, '2013-06-18'),
    (0x000206f2, 0x0039, '2015-07-26'),
    (0x00030650, 0x0009, '2012-01-18'),
    (0x00030651, 0x010d, '2013-05-20'),
    (0x00030651, 0x0110, '2013-10-14'),
    (0x00030660, 0x0003, '2010-11-03'),
    (0x00030661, 0x0106, '2011-06-23'),
    (0x00030661, 0x010d, '2011-12-22'),
    (0x00030661, 0x010f, '2015-07-21'),
    (0x00030669, 0x010d, '2013-05-15'),
    (0x00030671, 0x0117, '2013-04-10'),
    (0x00030672, 0x0218, '2013-07-22'),
    (0x00030672, 0x022d, '2014-01-14'),
    (0x00030672, 0x022e, '2014-04-01'),
    (0x00030673, 0x0325, '2014-11-19'),
    (0x00030673, 0x0326, '2018-01-10'),
    (0x00030678, 0x0832, '2015-02-09'),
    (0x00030678, 0x0836, '2018-01-10'),
    (0x00030679, 0x090a, '2018-01-10'),
    (0x000306a0, 0x0007, '2011-04-07'),
    (0x000306a2, 0x000c, '2011-07-25'),
    (0x000306a4, 0x0007, '2011-09-08'),
    (0x000306a5, 0x0009, '2011-11-10'),
    (0x000306a6, 0x0004, '2011-11-14'),
    (0x000306a8, 0x0010, '2012-02-20'),
    (0x000306a9, 0x0012, '2012-04-12'),
    (0x000306a9, 0x0013, '2012-07-16'),
    (0x000306a9, 0x0017, '2013-01-09'),
    (0x000306a9, 0x0019, '2013-06-13'),
    (0x000306a9, 0x001b, '2014-05-29'),
    (0x000306a9, 0x001c, '2015-02-26'),
    (0x000306a9, 0x001f, '2018-02-07'),
    (0x000306c3, 0x0012, '2013-07-02'),
    (0x000306c3, 0x0016, '2013-08-07'),
    (0x000306c3, 0x0017, '2013-08-16'),
    (0x000306c3, 0x001a, '2014-05-23'),
    (0x000306c3, 0x001c, '2014-07-03'),
    (0x000306c3, 0x001e, '2015-08-13'),
    (0x000306c3, 0x0020, '2016-03-16'),
    (0x000306c3, 0x0022, '2017-01-27'),
    (0x000306c3, 0x0023, '2017-11-20'),
    (0x000306c3, 0x0024, '2018-01-21'),
    (0x000306d4, 0x0018, '2014-12-05'),
    (0x000306d4, 0x0022, '2015-09-11'),
    (0x000306d4, 0x0024, '2016-04-29'),
    (0x000306d4, 0x0025, '2017-01-27'),
    (0x000306d4, 0x0028, '2017-11-17'),
    (0x000306d4, 0x002a, '2018-01-18'),
    (0x000306e0, 0x0008, '2012-07-26'),
    (0x000306e2, 0x020d, '2013-03-21'),
    (0x000306e3, 0x0308, '2013-03-21'),
    (0x000306e4, 0x0415, '2013-06-13'),
    (0x000306e4, 0x0416, '2013-07-09'),
    (0x000306e4, 0x0427, '2014-04-10'),
    (0x000306e4, 0x0428, '2014-05-29'),
    (0x000306e4, 0x042a, '2017-12-01'),
    (0x000306e4, 0x042c, '2018-01-25'),
    (0x000306e6, 0x0600, '2013-06-19'),
    (0x000306e7, 0x070c, '2014-04-14'),
    (0x000306e7, 0x070d, '2014-05-29'),
    (0x000306e7, 0x0713, '2018-02-16'),
    (0x000306f1, 0x0014, '2014-01-10'),
    (0x000306f2, 0x0029, '2014-09-03'),
    (0x000306f2, 0x002d, '2014-11-21'),
    (0x000306f2, 0x0036, '2015-08-10'),
    (0x000306f2, 0x0038, '2016-03-28'),
    (0x000306f2, 0x0039, '2016-10-07'),
    (0x000306f2, 0x003a, '2017-01-30'),
    (0x000306f2, 0x003b, '2017-11-17'),
    (0x000306f2, 0x003c, '2018-01-19'),
    (0x000306f2, 0x0f07, '2014-07-07'),
    (0x000306f3, 0x000d, '2016-02-11'),
    (0x000306f4, 0x0009, '2015-07-17'),
    (0x000306f4, 0x000a, '2016-02-11'),
    (0x000306f4, 0x000d, '2016-06-07'),
    (0x000306f4, 0x000f, '2017-01-30'),
    (0x000306f4, 0x0010, '2017-11-17'),
    (0x000306f4, 0x0011, '2018-01-22'),
    (0x00040651, 0x0015, '2013-07-02'),
    (0x00040651, 0x0016, '2013-08-08'),
    (0x00040651, 0x0017, '2013-09-14'),
    (0x00040651, 0x0018, '2014-05-23'),
    (0x00040651, 0x001c, '2014-07-03'),
    (0x00040651, 0x001d, '2015-08-13'),
    (0x00040651, 0x001f, '2016-04-01'),
    (0x00040651, 0x0020, '2017-01-27'),
    (0x00040651, 0x0021, '2017-11-20'),
    (0x00040651, 0x0023, '2018-01-18'),
    (0x00040661, 0x000f, '2013-08-21'),
    (0x00040661, 0x0010, '2014-05-23'),
    (0x00040661, 0x0012, '2014-07-03'),
    (0x00040661, 0x0016, '2016-04-01'),
    (0x00040661, 0x0017, '2017-01-27'),
    (0x00040661, 0x0018, '2017-11-20'),
    (0x00040661, 0x0019, '2018-01-21'),
    (0x00040671, 0x0013, '2015-08-03'),
    (0x00040671, 0x0016, '2016-04-29'),
    (0x00040671, 0x0017, '2017-01-27'),
    (0x00040671, 0x001b, '2017-11-17'),
    (0x00040671, 0x001d, '2018-01-21'),
    (0x000406a8, 0x081f, '2014-08-12'),
    (0x000406a9, 0x081f, '2014-08-12'),
    (0x000406c1, 0x010b, '2014-08-14'),
    (0x000406c2, 0x0221, '2015-02-18'),
    (0x000406c3, 0x0367, '2017-12-25'),
    (0x000406c4, 0x0410, '2018-01-04'),
    (0x000406d0, 0x000e, '2013-06-12'),
    (0x000406d8, 0x012a, '2018-01-04'),
    (0x000406e1, 0x0016, '2014-08-06'),
    (0x000406e1, 0x0020, '2014-11-11'),
    (0x000406e2, 0x000a, '2014-11-05'),
    (0x000406e2, 0x002c, '2015-05-21'),
    (0x000406e3, 0x008a, '2016-04-06'),
    (0x000406e3, 0x009e, '2016-06-22'),
    (0x000406e3, 0x00ba, '2017-04-09'),
    (0x000406e3, 0x00c2, '2017-11-16'),
    (0x000406e8, 0x0026, '2016-04-14'),
    (0x000406f0, 0x0014, '2015-07-02'),
    (0x000406f1, 0xb00001c, '2016-05-20'),
    (0x000406f1, 0xb00001d, '2016-06-06'),
    (0x000406f1, 0xb00001f, '2016-10-07'),
    (0x000406f1, 0xb000021, '2017-03-01'),
    (0x000406f1, 0xb000025, '2017-11-18'),
    (0x000406f1, 0xb00002c, '2018-03-21'),
    (0x00050653, 0x100013e, '2017-11-21'),
    (0x00050653, 0x1000140, '2018-01-29'),
    (0x00050654, 0x2000022, '2017-06-01'),
    (0x00050654, 0x2000035, '2017-10-17'),
    (0x00050654, 0x200003c, '2017-12-08'),
    (0x00050654, 0x2000043, '2018-01-26'),
    (0x00050662, 0x000f, '2015-12-12'),
    (0x00050662, 0x0014, '2017-12-16'),
    (0x00050662, 0x0015, '2018-01-22'),
    (0x00050663, 0x700000d, '2016-10-12'),
    (0x00050663, 0x7000011, '2017-12-16'),
    (0x00050663, 0x7000012, '2018-01-22'),
    (0x00050664, 0xf00000a, '2016-06-02'),
    (0x00050664, 0xf00000c, '2017-02-15'),
    (0x00050664, 0xf000011, '2018-01-22'),
    (0x00050665, 0xe000009, '2018-01-22'),
    (0x00050671, 0x01b6, '2018-01-08'),
    (0x000506a0, 0x0038, '2015-01-12'),
    (0x000506c2, 0x000e, '2017-06-06'),
    (0x000506c8, 0x0010, '2016-03-04'),
    (0x000506c9, 0x002c, '2017-03-25'),
    (0x000506c9, 0x002e, '2017-11-22'),
    (0x000506ca, 0x0008, '2017-11-22'),
    (0x000506d1, 0x0101, '2014-11-20'),
    (0x000506d1, 0x0102, '2015-06-05'),
    (0x000506e0, 0x0018, '2014-11-19'),
    (0x000506e1, 0x002a, '2015-06-02'),
    (0x000506e2, 0x002e, '2015-08-15'),
    (0x000506e3, 0x008a, '2016-04-06'),
    (0x000506e3, 0x009e, '2016-06-22'),
    (0x000506e3, 0x00ba, '2017-04-09'),
    (0x000506e3, 0x00c2, '2017-11-16'),
    (0x000506e8, 0x0034, '2016-07-10'),
    (0x000506f1, 0x0020, '2017-11-22'),
    (0x00060660, 0x000c, '2016-08-21'),
    (0x00060661, 0x000e, '2017-01-28'),
    (0x000706a0, 0x0026, '2017-07-12'),
    (0x000706a1, 0x001e, '2017-10-31'),
    (0x000706a1, 0x0022, '2017-12-26'),
    (0x00080650, 0x0018, '2018-01-08'),
    (0x000806e9, 0x0062, '2017-04-27'),
    (0x000806e9, 0x0080, '2018-01-04'),
    (0x000806e9, 0x0084, '2018-01-21'),
    (0x000806ea, 0x0066, '2017-05-23'),
    (0x000806ea, 0x0070, '2017-08-03'),
    (0x000806ea, 0x0080, '2018-01-04'),
    (0x000806ea, 0x0084, '2018-01-21'),
    (0x000906e9, 0x005e, '2017-04-06'),
    (0x000906e9, 0x0080, '2018-01-04'),
    (0x000906e9, 0x0084, '2018-01-21'),
    (0x000906ea, 0x0070, '2017-08-23'),
    (0x000906ea, 0x0080, '2018-01-04'),
    (0x000906ea, 0x0084, '2018-01-21'),
    (0x000906eb, 0x0072, '2017-09-20'),
    (0x000906eb, 0x0080, '2018-01-04'),
    (0x000906eb, 0x0084, '2018-01-21'),
)

# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/include/asm/cputype.h
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/cpuinfo.c
AARCH64_PARTS = {
    0x41: ('ARM Limited', {  # 'A'
        0xd00: 'Foundation',
        0xd03: 'Cortex-A53',
        0xd04: 'Cortex-A35',
        0xd05: 'Cortex-A55',
        0xd07: 'Cortex-A57',
        0xd08: 'Cortex-A72',
        0xd09: 'Cortex-A73',
        0xd0a: 'Cortex-A75',
        0xd0f: 'AEM-v8',
    }),
    0x42: ('Broadcom', {  # 'B'
        0x516: 'Vulcan',
    }),
    0x43: ('Cavium', {  # 'C'
        0x0a1: 'ThunderX',
        0x0a2: 'ThunderX 81XX',
        0x0a3: 'ThunderX 83XX',
        0x0af: 'ThunderX 2',
    }),
    0x4e: ('NVidia', {  # 'N'
        0x003: 'Denver',
        0x004: 'Carmel',
    }),
    0x50: ('Applied Micro', {  # 'P'
        0x000: 'Potenza',
    }),
    0x51: ('Qualcomm', {  # 'Q'
        0x200: 'Kryo',
        0x800: 'Falkor v1',
        0xc00: 'Falkor',
    }),
}


class CPUInfo(object):
    """Information about a CPU"""
    def __init__(self, architecture):
        self.architecture = architecture

    @staticmethod
    def decode_cpuinfo(filename=None):
        """Build a CPUInfo object from /proc/cpuinfo content"""
        field_names = set((
            # x86
            'vendor_id',
            'cpu family',
            'model',
            'model name',
            'stepping',
            'microcode',

            # aarch64
            'CPU implementer',
            'CPU architecture',
            'CPU variant',
            'CPU part',
            'CPU revision',
        ))
        fields = {}
        if filename is None:
            filename = '/proc/cpuinfo'
            if not os.path.exists(filename):
                logger.debug("%s does not exist, skipping it", filename)
                return

        logger.debug("Reading %r", filename)
        with open(filename, 'r') as cpuinfo_file:
            for line in cpuinfo_file:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    if key in field_names:
                        # Decode the value if it is an int
                        if re.match(r'^[0-9]+$', value):
                            value = int(value)
                        elif re.match(r'^0x[0-9a-fA-F]+$', value):
                            value = int(value[2:], 16)
                        cur_value = fields.get(key)
                        if cur_value is None:
                            fields[key] = value
                        elif cur_value != value:
                            logger.error(
                                "CPU with different information: %s is %r and %r",
                                key, cur_value, value)

        vendor_id = fields.get('vendor_id')
        model_name = fields.get('model name')
        microcode_version = fields.get('microcode')
        if vendor_id is not None and model_name is not None:
            cpuid = None
            family = fields.get('cpu family')
            model = fields.get('model')
            stepping = fields.get('stepping')
            if family is not None and model is not None and stepping is not None:
                cpuid = (
                    ((model & 0xf0) << 12) |
                    (family << 8) |
                    ((model & 0xf) << 4) |
                    stepping)
            if cpuid is None:
                logger.error("CPUID components not found in %s", filename)
                return

            return X86CPUInfo(vendor_id, model_name, cpuid, microcode_version)

        implementer = fields.get('CPU implementer')
        architecture = fields.get('CPU architecture')
        if implementer is not None and architecture is not None:
            variant = fields.get('CPU variant')
            part = fields.get('CPU part')
            revision = fields.get('CPU revision')
            return Aarch64CPUInfo(implementer, architecture, variant, part, revision)

        logger.error(
            "Unable to find key fields in %s (vendor_id, CPU implementer, etc.)",
            filename)


class Aarch64CPUInfo(CPUInfo):
    """Information about an Aarch64 (ARM64) CPU from MIDR_EL1 register

    MIDR: Main ID Register
        ARM64: MRS <Xt>, MIDR_EL1
        ARM32: MRC p15, 0, <Rt>, c0, c0, 0

    It is also accessible from
    /sys/devices/system/cpu/cpu0/regs/identification/midr_el1
    """
    def __init__(self, implementer, architecture, variant, part, revision):
        super(Aarch64CPUInfo, self).__init__('aarch64')
        self.implementer = implementer
        self.architecture = architecture
        self.variant = variant
        self.part = part
        self.revision = revision

    def unique_key(self):
        """Get a unique key representing the CPU"""
        return self.architecture, self.implementer, self.architecture, self.variant, self.part, self.revision

    def __repr__(self):
        return '{}({}, {}, {}, {})'.format(
            self.__class__.__name__,
            hex(self.implementer),
            hex(self.architecture),
            hex(self.variant),
            hex(self.part),
            hex(self.revision))

    def describe(self):
        impl_data = AARCH64_PARTS.get(self.implementer)
        if impl_data is not None:
            impl_name, impl_parts = impl_data
        else:
            impl_name = '?'
            impl_parts = {}

        print("- Implementer: {} ({:#x})".format(impl_name, self.implementer))
        print("- Part: {} ({:#x})".format(impl_parts.get(self.part, '?'), self.part))
        print("- Architecture: {}".format(self.architecture))
        print("- Variant: {:#x}".format(self.variant))
        print("- Revision: {}".format(self.revision))


class X86CPUInfo(CPUInfo):
    """Information about an x86 CPU"""
    def __init__(self, vendor_id, model_name, cpuid, microcode_version=None):
        super(X86CPUInfo, self).__init__('x86')
        self.vendor_id = vendor_id
        self.model_name = model_name
        self.cpuid = cpuid
        self.microcode_version = microcode_version

    def unique_key(self):
        """Get a unique key representing the CPU"""
        return self.architecture, self.vendor_id, self.model_name, self.cpuid

    def __repr__(self):
        return '{}({}, {}, {}, {})'.format(
            self.__class__.__name__,
            repr(self.vendor_id),
            repr(self.model_name),
            hex(self.cpuid),
            hex(self.microcode_version) if self.microcode_version is not None else 'None')

    @property
    def x86_family(self):
        return ((self.cpuid >> 8) & 0xf) + ((self.cpuid >> 20) & 0xff)

    @property
    def x86_model(self):
        return ((self.cpuid >> 4) & 0xf) + ((self.cpuid >> 12) & 0xf0)

    @property
    def x86_stepping(self):
        return self.cpuid & 0xf

    def desc_cpuid(self):
        """Describe the cpuid signature in a list of strings"""
        lines = ["{0:#x} (family {1:d} model {2:d}={2:#x} stepping {3:d})".format(
            self.cpuid, self.x86_family, self.x86_model, self.x86_stepping)]
        cpu_models = CPU_MODELS.get(self.vendor_id, {}).get(self.x86_family)
        if cpu_models is not None:
            cpuid_data = cpu_models.get((self.x86_model, self.x86_stepping))
            if cpuid_data is None:
                cpuid_data = cpu_models.get((self.x86_model, -1))
            if cpuid_data is None:
                logger.warning("Unknown CPU family %d model %#x stepping %d",
                               self.x86_family, self.x86_model, self.x86_stepping)
            else:
                second_line = cpuid_data[1]
                if cpuid_data[0] is not None:
                    second_line = '"{}" {}'.format(cpuid_data[0], second_line)
                lines.append(second_line)
                if len(cpuid_data) > 2:
                    assert len(cpuid_data) == 3
                    for public_name in cpuid_data[2]:
                        lines.append("    {}".format(public_name))
        return lines

    def desc_microcode_version(self):
        """Describe the microcode version in a list of strings"""
        if self.microcode_version is None:
            return ['unknown']
        microcode_list = []
        version_date = None
        available_upgrade_ver = None
        available_upgrade_date = None
        if self.vendor_id == 'GenuineIntel':
            for known_cpuid, known_ver, update_date in INTEL_UCODE_VERSIONS:
                if known_cpuid != self.cpuid:
                    continue
                microcode_list.append((known_ver, update_date))
                if self.microcode_version == known_ver:
                    version_date = update_date
                elif self.microcode_version < known_ver:
                    if available_upgrade_ver is None or available_upgrade_ver < known_ver:
                        available_upgrade_ver = known_ver
                        available_upgrade_date = update_date

        desc = "{:#x}".format(self.microcode_version)
        if version_date:
            desc += " from {}".format(version_date)
        lines = [desc]
        if available_upgrade_date and available_upgrade_date != version_date:
            lines.append("Available upgrade {:#x} from {}".format(
                available_upgrade_ver, available_upgrade_date))
        if microcode_list:
            microcode_list.sort()
            lines.append("Known microcode versions:")
            is_current_present = False
            for known_ver, update_date in microcode_list:
                if not is_current_present and known_ver > self.microcode_version:
                    lines.append("    ({:#x} - current)".format(self.microcode_version))
                    is_current_present = True
                lines.append("    {:#x} from {}".format(known_ver, update_date))
                if self.microcode_version == known_ver:
                    lines[-1] += " (current)"
                    is_current_present = True
            if not is_current_present:
                # The list of known microcode is outdated
                logger.warning("Current microcode version is newer than known ones")
        return lines

    def describe(self):
        print("- Vendor ID: {}".format(self.vendor_id))
        print("- Model name: {}".format(self.model_name))
        cpuid_lines = self.desc_cpuid()
        print("- CPUID: {}".format(cpuid_lines[0]))
        for line in cpuid_lines[1:]:
            print("    {}".format(line))
        microcode_lines = self.desc_microcode_version()
        print("- Microcode version: {}".format(microcode_lines[0]))
        for line in microcode_lines[1:]:
            print("    {}".format(line))

    @classmethod
    def decode_x86_cpuid(cls):
        """Run cpuid if on x86 to get the relevant CPUInfo"""
        plat_mach = platform.machine()
        plat_sys = platform.system()
        if plat_mach in ('AMD64', 'x86_64'):
            ptrsize = 64
        elif plat_mach in ('x86', 'i686'):
            ptrsize = 32
        else:
            logger.warning("Not using x86 cpuid instruction on %s", platform.machine())
            return

        if ptrsize != ctypes.sizeof(ctypes.c_voidp) * 8:
            logger.error(
                "platform.machine() %r is inconsistent with sizeof(void*) = %d",
                plat_mach, ctypes.sizeof(ctypes.c_voidp))
            return

        # Find a assembly function which performs:
        # void do_cpuid(uint32_t regs[4]) // regs are eax, ebx, ecx, edx
        # {
        #     __asm__ volatile ("cpuid"
        #         :"=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
        #         :"0"(regs[0]), "1"(regs[1]), "2"(regs[2]), "3"(regs[3]));
        # }
        cpuid_functions = {
            'cdecl.x86_32':
                # Arg on stack, ebx as PIC register, esi preserved
                #  0:  56               push   %esi
                #  1:  53               push   %ebx
                #  2:  8b 74 24 0c      mov    0xc(%esp),%esi
                #  6:  8b 06            mov    (%esi),%eax
                #  8:  8b 5e 04         mov    0x4(%esi),%ebx
                #  b:  8b 4e 08         mov    0x8(%esi),%ecx
                #  e:  8b 56 0c         mov    0xc(%esi),%edx
                # 11:  0f a2            cpuid
                # 13:  89 06            mov    %eax,(%esi)
                # 15:  89 5e 04         mov    %ebx,0x4(%esi)
                # 18:  89 4e 08         mov    %ecx,0x8(%esi)
                # 1b:  89 56 0c         mov    %edx,0xc(%esi)
                # 1e:  5b               pop    %ebx
                # 1f:  5e               pop    %esi
                # 20:  c3               ret
                b'VS\x8bt$\x0c\x8b\x06\x8b^\x04\x8bN\x08\x8bV\x0c' +
                b'\x0f\xa2\x89\x06\x89^\x04\x89N\x08\x89V\x0c[^\xc3',
            'Linux.x86_64':
                # Arg is rdi, rbx preserved
                #  0:  53               push   %rbx
                #  1:  8b 07            mov    (%rdi),%eax
                #  3:  8b 5f 04         mov    0x4(%rdi),%ebx
                #  6:  8b 4f 08         mov    0x8(%rdi),%ecx
                #  9:  8b 57 0c         mov    0xc(%rdi),%edx
                #  c:  0f a2            cpuid
                #  e:  89 5f 04         mov    %ebx,0x4(%rdi)
                # 11:  89 07            mov    %eax,(%rdi)
                # 13:  89 4f 08         mov    %ecx,0x8(%rdi)
                # 16:  89 57 0c         mov    %edx,0xc(%rdi)
                # 19:  5b               pop    %rbx
                # 1a:  c3               retq
                b'S\x8b\x07\x8b_\x04\x8bO\x08\x8bW\x0c' +
                b'\x0f\xa2\x89_\x04\x89\x07\x89O\x08\x89W\x0c[\xc3',
            'Windows.x86_64':
                # Args is rcx, rbx preserved
                #  0: 53                push   %rbx
                #  1: 8b 01             mov    (%rcx),%eax
                #  3: 8b 59 04          mov    0x4(%rcx),%ebx
                #  6: 49 89 c8          mov    %rcx,%r8
                #  9: 8b 49 08          mov    0x8(%rcx),%ecx
                #  c: 41 8b 50 0c       mov    0xc(%r8),%edx
                # 10: 0f a2             cpuid
                # 12: 41 89 00          mov    %eax,(%r8)
                # 15: 41 89 58 04       mov    %ebx,0x4(%r8)
                # 19: 41 89 48 08       mov    %ecx,0x8(%r8)
                # 1d: 41 89 50 0c       mov    %edx,0xc(%r8)
                # 21: 5b                pop    %rbx
                # 22: c3                retq
                b'S\x8b\x01\x8bY\x04I\x89\xc8\x8bI\x08A\x8bP\x0c' +
                b'\x0f\xa2A\x89\x00A\x89X\x04A\x89H\x08A\x89P\x0c[\xc3',
        }
        cpuid_functions_map = {
            ('Linux', 32): cpuid_functions['cdecl.x86_32'],
            ('Linux', 64): cpuid_functions['Linux.x86_64'],
            ('Windows', 32): cpuid_functions['cdecl.x86_32'],
            ('Windows', 64): cpuid_functions['Windows.x86_64'],
        }
        cpuid_func = cpuid_functions_map.get((plat_sys, ptrsize))
        if cpuid_func is None:
            logger.error("Unsupported operating system")
            return

        logger.debug("Using CPUID instruction for %d-bit %s", ptrsize, plat_sys)

        if plat_sys == 'Linux':
            # Find functions in libc
            libc = ctypes.CDLL(ctypes.util.find_library('c'))
            libc.mmap.restype = ctypes.c_void_p
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

            # Allocate memory with a RW private anonymous mmap
            # PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
            mem = libc.mmap(0, len(cpuid_func), 3, 0x22, -1, 0)
            if int(mem) & 0xffffffff == 0xffffffff:
                libc.perror(b"mmap")
                return

            # Copy the function
            ctypes.memmove(mem, cpuid_func, len(cpuid_func))

            # Change protection to RX
            if libc.mprotect(mem, len(cpuid_func), 5) == -1:
                libc.perror(b"mprotect")
                libc.munmap(mem, len(cpuid_func))
                return

            # Transmute the memory to a suitable function
            memfun = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(mem)

            # Use it and free it
            result = cls.decode_x86_cpuid_with_helper(memfun)
            libc.munmap(mem, len(cpuid_func))
            return result

        if plat_sys == 'Windows':
            # https://github.com/flababah/cpuid.py/blob/master/cpuid.py says:
            # VirtualAlloc seems to fail under some weird
            # circumstances when ctypes.windll.kernel32 is
            # used under 64 bit Python. CDLL fixes this.
            if ptrsize == 64:
                k32 = ctypes.CDLL("kernel32.dll")
            else:
                k32 = ctypes.windll.kernel32
            k32.VirtualAlloc.restype = ctypes.c_void_p
            int_p = ctypes.POINTER(ctypes.c_int)
            k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                           ctypes.c_int, int_p]
            k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                        ctypes.c_int]

            # Allocate RW memory of type MEM_COMMIT | MEM_RESERVE (=0x1000|0x2000)
            # PAGE_READWRITE = 4
            mem = k32.VirtualAlloc(0, len(cpuid_func), 0x3000, 4)
            if not mem:
                sys.stderr.write("VirtualAlloc: {}\n".format(ctypes.FormatError()))
                return

            # Copy the function
            ctypes.memmove(mem, cpuid_func, len(cpuid_func))

            # Change protection to PAGE_EXECUTE_READ = 0x20
            oldprot = ctypes.c_int()
            if not k32.VirtualProtect(mem, len(cpuid_func), 32, ctypes.byref(oldprot)):
                sys.stderr.write("VirtualProtect: {}\n".format(ctypes.FormatError()))
                # MEM_RELEASE = 0x8000
                k32.VirtualFree(mem, len(cpuid_func), 0x8000)
                return

            # Transmute the memory to a suitable function
            memfun = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(mem)

            # Use it and free it
            result = cls.decode_x86_cpuid_with_helper(memfun)
            k32.VirtualFree(mem, len(cpuid_func), 0x8000)
            return result

    @classmethod
    def decode_x86_cpuid_with_helper(cls, cpuid_function):
        def cpuid(code):
            regs = (ctypes.c_uint32 * 4)()
            regs[0] = code
            cpuid_function(regs)
            return regs
        max_code, vendor0, vendor2, vendor1 = cpuid(0)
        vendor_id = struct.pack('<III', vendor0, vendor1, vendor2)
        cpuid_1 = cpuid(1)[0] if max_code >= 1 else 0

        max_extcode = cpuid(0x80000000)[0]
        if max_extcode >= 0x80000004:
            brand_string = b''
            for i in range(3):
                eax, ebx, ecx, edx = cpuid(0x80000002 + i)
                brand_string += struct.pack('<IIII', eax, ebx, ecx, edx)
            model_name = brand_string.decode('ascii').rstrip('\0')
        else:
            model_name = None
        return X86CPUInfo(vendor_id.decode('ascii'), model_name, cpuid_1)


def main(argv=None):
    """Program entry point"""
    parser = argparse.ArgumentParser(description="Find the CPU model")
    parser.add_argument('cpuinfo', nargs='*', type=str,
                        help="analyze the given /proc/cpuinfo files")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-l', '--list', action='store_true',
                        help="list known CPUIDs")
    parser.add_argument('-m', '--list-microcodes', action='store_true',
                        help="list known Microcodes")
    args = parser.parse_args(argv)
    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    if args.list:
        for model, stepping in sorted(INTEL_FAM6_MODELS.keys()):
            cpuid = (6 << 8)  # family
            cpuid |= ((model & 0xf0) << 12) | ((model & 0xf) << 4)
            cpuid |= stepping & 0xf
            cpuinfo = X86CPUInfo('GenuineIntel', None, cpuid)
            desc_list = cpuinfo.desc_cpuid()
            desc = ' '.join(desc_list[:2])
            if stepping < 0:
                desc = desc.replace(' stepping 15', '')
            print(desc)
            if len(desc_list) > 2:
                print('\n'.join(desc_list[2:]))

    if args.list_microcodes:
        ucodes_for_cpuid = {}
        for cpuid, microcode_version, update_date in INTEL_UCODE_VERSIONS:
            if cpuid not in ucodes_for_cpuid:
                ucodes_for_cpuid[cpuid] = {}
            if microcode_version not in ucodes_for_cpuid[cpuid]:
                ucodes_for_cpuid[cpuid][microcode_version] = update_date
            elif ucodes_for_cpuid[cpuid][microcode_version] < update_date:
                # This can occur if a platform received an update with a
                # different date
                ucodes_for_cpuid[cpuid][microcode_version] = update_date
        for cpuid, ucodes in sorted(ucodes_for_cpuid.items()):
            cpuinfo = X86CPUInfo('GenuineIntel', None, cpuid)
            desc_list = cpuinfo.desc_cpuid()
            print('Intel {}'.format(' '.join(desc_list[:2])))
            for microcode_version, update_date in sorted(ucodes.items()):
                print('    Microcode version {:#x} {}'.format(
                    microcode_version, update_date))
            print('')

    if args.list or args.list_microcodes:
        return 0

    if args.cpuinfo:
        for ifile, filename in enumerate(args.cpuinfo):
            if ifile > 0:
                print('')
            cpuinfo = CPUInfo.decode_cpuinfo(filename)
            if cpuinfo is not None:
                print("{}:".format(filename))
                cpuinfo.describe()
    else:
        cpuinfo_proc = CPUInfo.decode_cpuinfo()
        cpuinfo_x86 = X86CPUInfo.decode_x86_cpuid()
        if cpuinfo_proc is not None:
            cpuinfo = cpuinfo_proc
            cpuinfo_k = cpuinfo.unique_key()
            if cpuinfo_x86 is not None and cpuinfo_x86.unique_key() != cpuinfo_k:
                logger.warning("/proc/cpuinfo and cpuid disagree: %r vs %r",
                               cpuinfo_proc, cpuinfo_x86)
        elif cpuinfo_x86 is not None:
            cpuinfo = cpuinfo_x86
        else:
            logger.error("Unable to find a source of CPU information")
            return 1
        cpuinfo.describe()

    return 0


if __name__ == '__main__':
    sys.exit(main())
