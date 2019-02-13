#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2017-2019 Nicolas Iooss
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
"""Draw a circle from a fast oscillator

Inspired from the csound's function fastoscil
https://github.com/csound/csound/blob/495bb9cfd5bc4d19ce02a988fba3764b4141c850/OOps/pstream.c#L183-L192

Usage:

    ./graphviz_oscillator.py |dot -Kneato -n -Tsvg -o graphviz_oscillator.out.svg

@author: Nicolas Iooss
@license: MIT
"""
print('graph {')
print('    splines="line"')
x = 1.
y = 0.
a = .09
for i in range(70):
    print('    n%d [shape=circle,label="%02d",pos="%d,%d!"]' % (i, i, 500 * x, 500 * y))
    ox, oy = x, y
    x = x - a * y
    y = y + a * x
    if y < -1:
        y = -1.
    if y > 1:
        y = 1.

    if i >= 35:
        # Draw approximative diameters
        print('    n%d -- n%d' % (i - 35, i))
print('}')
