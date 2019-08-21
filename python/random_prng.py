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
"""Implement several Pseudo-Random Number Generators (PRNG)

PRNG algorithms use a seed, which is a number from which a sequence of numbers
is computed. The result of a "get_random" function usually consists in a part
of a number of this sequence (this part being not large enough to compromise
the current seed which is in use).
This enables producing reproducible results with an algorithm which would use
random number.

Some projects which implements PRNG:
* https://github.com/cmcqueen/simplerandom
"""
import binascii
import struct


class GlibcRandom(object):
    """GLIBC srand() and rand()

    https://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/random_r.c;hb=glibc-2.28
    https://www.mscs.dal.ca/~selinger/random/
    https://gist.github.com/integeruser/4cca768836c68751904fe215c94e914c
    """
    def __init__(self, seed):
        # Convert the seed to a 32-bit signed integer
        seed = seed & 0xffffffff
        if seed & 0x80000000:
            seed -= 0x100000000
        self.r_state = [None] * 34
        self.r_state[0] = seed
        for i in range(1, 31):
            # Do state[i] = (16807 * state[i - 1]) % 2147483647 without overflowing 31 bits
            # 16807*s = 16807*(127773*high + low) = (16807*127773)*high + 16807*low
            # 16807*127773 = 0x7ffff4eb = 2147483647 - 2836
            high, low = divmod(seed, 127773)
            new_word = 16807 * low - 2836 * high
            if new_word < 0:
                new_word += 0x7fffffff
            seed = (16807 * seed) % 2147483647
            assert seed == new_word
            self.r_state[i] = seed
        for i in range(31, 34):
            self.r_state[i] = self.r_state[i - 31]
        self.index = 0

        # Throw away the first iterations
        for _ in range(34, 344):
            self.get_next()

    def get_next(self):
        """Get the next random sample from the internal state"""
        value = (self.r_state[(self.index - 31) % 34] + self.r_state[(self.index - 3) % 34]) & 0xffffffff
        self.r_state[self.index] = value
        self.index = (self.index + 1) % 34
        return value >> 1

    @classmethod
    def self_test(cls):
        """Test things"""
        test_cases = [
            # https://www.mscs.dal.ca/~selinger/random/
            (1, (
                1804289383, 846930886, 1681692777, 1714636915, 1957747793,
                424238335, 719885386, 1649760492, 596516649, 1189641421,
            )),
        ]
        # https://gist.github.com/integeruser/4cca768836c68751904fe215c94e914c
        test_cases += [
            (1337, (
                292616681, 1638893262, 255706927, 995816787, 588263094,
                1540293802, 343418821, 903681492, 898530248, 1459533395,
            )),
            (0x1fffffffd, (
                853660264, 1568971201, 1203662233, 15207980, 1421679843,
                1717493552, 811896681, 155106358, 1156099704, 428649477,
            )),
            (-1337, (
                1766598330, 413225925, 1792113474, 2120225281, 1445538174,
                488114690, 1678701932, 1108308242, 32946609, 1612248994,
            )),
            (-0x1fffffffe, (
                1505335290, 1738766719, 190686788, 260874575, 747983061,
                906156498, 1502820864, 142559277, 1261608745, 1380759627,
            )),
        ]
        for seed, expected in test_cases:
            prng = cls(seed)
            generated = tuple(prng.get_next() for _ in range(len(expected)))
            assert generated == expected


class GlibcLcgRandom(object):
    """GLIBC "TYPE_0" Linear Congruential Generator (LCG) srand() and rand()

    https://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/random_r.c;hb=glibc-2.28
    """
    def __init__(self, seed):
        self.value = seed

    def get_next(self):
        """Get the next random sample from the internal state"""
        self.value = (self.value * 1103515245 + 12345) & 0x7fffffff
        # Some websites use self.value/65536 as return value
        return self.value

    @classmethod
    def self_test(cls):
        """Test things"""
        expected = (
            12345, 1406932606, 654583775, 1449466924, 229283573,
            1109335178, 1051550459, 1293799192, 794471793, 551188310,
        )
        prng = cls(0)
        generated = tuple(prng.get_next() for _ in range(len(expected)))
        assert generated == expected


class MsvcrtRandom(object):
    """MSVCRT (Microsoft Visual C++ RunTime) srand() and rand()"""
    def __init__(self, seed):
        self.value = seed

    def get_next(self):
        """Get the next random sample from the internal state"""
        self.value = (self.value * 214013 + 2531011) & 0xffffffff
        return (self.value >> 16) & 0x7fff

    @classmethod
    def self_test(cls):
        """Test things"""
        # https://github.com/goto-bus-stop/msvcrt-rand/blob/v1.0.0/test/index.js
        expected = (162, 22942, 11948, 32107, 7593, 29941, 28334, 19353, 15298, 26361)
        prng = cls(38)
        generated = tuple(prng.get_next() for _ in range(len(expected)))
        assert generated == expected


class CSharpRandom(object):
    """C# (and .NET) class System.Random

    https://docs.microsoft.com/en-us/dotnet/api/system.random
        The current implementation of the Random class is based on a modified version
        of Donald E. Knuth's subtractive random number generator algorithm.
        For more information, see D. E. Knuth. The Art of Computer Programming,
        Volume 2: Seminumerical Algorithms. Addison-Wesley, Reading, MA, third edition, 1997.
    https://referencesource.microsoft.com/#mscorlib/system/random.cs,92e3cf6e56571d5a,references
        This algorithm comes from Numerical Recipes in C (2nd Ed.)
        Apparently the range [1..55] is special (Knuth) and so we're wasting the 0'th position.
    """
    MSEED = 161803398  # = 0x9a4ec86
    MBIG = 0x7fffffff  # Int32.MaxValue

    def __init__(self, seed):
        mj = self.MSEED - abs(seed)
        self.seed_array = [None] * 56
        self.seed_array[55] = mj
        mk = 1
        for i in range(1, 55):
            ii = (21 * i) % 55
            self.seed_array[ii] = mk
            mk = mj - mk
            if mk < 0:
                mk += self.MBIG
            mj = self.seed_array[ii]

        for _ in range(1, 5):
            for i in range(1, 56):
                self.seed_array[i] -= self.seed_array[1 + (i + 30) % 55]
                if self.seed_array[i] < 0:
                    self.seed_array[i] += self.MBIG

        assert self.seed_array[0] is None
        assert all(0 <= x < self.MBIG for x in self.seed_array[1:])
        self.inext = 0
        self.inextp = 21

    def get_next(self):
        """Get the next random sample from the internal state"""
        inext = self.inext + 1
        inextp = self.inextp + 1
        if inext >= 56:
            inext = 1
        if inextp >= 56:
            inextp = 1

        value = self.seed_array[inext] - self.seed_array[inextp]
        if value == self.MBIG:
            value -= 1
        elif value < 0:
            value += self.MBIG
        assert 0 <= value < self.MBIG
        self.seed_array[inext] = value
        self.inext = inext
        self.inextp = inextp
        return value

    def next_bytes(self, size):
        """Get bytes for the given size"""
        return b''.join(struct.pack('B', self.get_next() & 0xff) for _ in range(size))

    @classmethod
    def self_test(cls):
        """Test things"""
        # https://www.fireeye.com/blog/threat-research/2018/10/2018-flare-on-challenge-solutions.html
        # Level 2 (Minesweeper)
        expected = binascii.unhexlify(b'b62372ef302216ca153e52f5d3f88dac4b0b09f35a37a2a503bcf57517849e3b')
        prng = cls(0xee97f60)
        assert prng.next_bytes(32) == expected


def run_tests():
    """Run every testsuite"""
    print("Runinng GLIBC tests")
    GlibcRandom.self_test()
    print("Runinng GLIBC LCG tests")
    GlibcLcgRandom.self_test()
    print("Runinng MSVCRT tests")
    MsvcrtRandom.self_test()
    print("Runinng C# and .NET tests")
    CSharpRandom.self_test()


if __name__ == '__main__':
    run_tests()
