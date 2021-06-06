#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2015-2018 Nicolas Iooss
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
"""Examples of use of z3 to solve some problems

Common z3 pitfalls:

* Operator __rshift__ (">>") is the arithmetic shift right, which sign-extends
  values. In order to use the logical shift right (which does not sign-entend),
  use z3.LShR. If the arithmetic shift right is never used, this is possible:

    z3.BitVecRef.__rshift__  = z3.LShR

* Comparison operators ("<", ">", etc.) performs signed comparison. Unsigned
  comparisons are:

    * z3.UGT for > (Unsigned Greater Than)
    * z3.ULT for < (Unsigned Lower Than)

* Integers do not overflow their size. In order to use a 8-bit variable as a
  64-bit integer, use:

    * z3.Concat(z3.BitVecVal(0, 64 - 8), value)
    * z3.ZeroExt(64 - value.size(), value)

  Example:

    >>> value = z3.BitVec('value', 8)
    >>> z3.simplify(z3.ZeroExt(64 - value.size(), value))
    Concat(0, value)
    >>> _.size()
    64

Some publications of z3 users:

* https://doar-e.github.io/blog/2014/10/11/taiming-a-wild-nanomite-protected-mips-binary-with-symbolic-execution-no-such-crackme/  # noqa, pylint:disable=line-too-long
  Taming a wild nanomite-protected MIPS binary with symbolic execution: No Such Crackme
* http://www.phrack.org/issues/69/4.html#article
  Phrak Volume 0x0f, Issue 0x45, Phile #0x04 of 0x10 Linenoise
* https://wiremask.eu/writeups/hackingweek-2015-reverse-4/
  HackingWeek 2015 - Reverse 4

@author: Nicolas Iooss
@license: MIT
"""
import binascii
import hashlib
import struct
import z3


# Standard polynoms
POLY_CRC32 = 0x04c11db7
POLY_CRC32C = 0x1edc6f41  # Castagnoli, SSE4.2 "CRC32" instruction
POLY_CRC32K = 0x741b8cd7  # Koopman
POLY_CRC32Q = 0x814141ab


def reverse32_bits(num):
    """Reverse the bits of a 32-bit number"""
    num = ((num & 0x55555555) << 1) | ((num & 0xaaaaaaaa) >> 1)
    num = ((num & 0x33333333) << 2) | ((num & 0xcccccccc) >> 2)
    num = ((num & 0x0f0f0f0f) << 4) | ((num & 0xf0f0f0f0) >> 4)
    num = ((num & 0x00ff00ff) << 8) | ((num & 0xff00ff00) >> 8)
    num = ((num & 0x0000ffff) << 16) | ((num & 0xffff0000) >> 16)
    assert (num & ~0xffffffff) == 0
    return num


def z3_rol32(value, count):
    """Rotate count times a 32-bit value to the left"""
    assert value.size() == 32
    if count in (0, 32):
        return value
    return z3.Concat(z3.Extract(31 - count, 0, value), z3.Extract(31, 32 - count, value))


def z3_ror32(value, count):
    """Rotate count times a 32-bit value to the right"""
    assert value.size() == 32
    if count in (0, 32):
        return value
    return z3.Concat(z3.Extract(count - 1, 0, value), z3.Extract(31, count, value))


POLY_CRC32_REV = reverse32_bits(POLY_CRC32)


def get_solutions(solver):
    """Enumerate the solutions of a solver instance"""
    while solver.check() == z3.sat:
        model = solver.model()
        yield model
        # Add an equation which removes the found model from the results
        solver.add(z3.Or([sym() != model[sym] for sym in model.decls()]))


def hexlify_bksl(data):
    """Encode bytes into an hexadecimal string with backslashes"""
    hexstr = binascii.hexlify(data).decode('ascii')
    return ''.join('\\x' + hexstr[i:i + 2] for i in range(0, len(hexstr), 2))


def test_rotate_operations():
    """Ensure that rotate operations operate correctly"""
    x = z3.BitVec('x', 32)
    for count in range(0, 33):
        result = z3_rol32(x, count)
        check = z3.simplify(result == (x << count) | z3.LShR(x, 32 - count))
        assert repr(check) == "True", "Unable to simplify z3 assertion {}".format(check)

        result = z3_ror32(result, count)
        check = z3.simplify(result == x)
        assert repr(check) == "True", "Unable to simplify z3 assertion {}".format(check)

        result = z3_ror32(x, count)
        check = z3.simplify(result == (x << (32 - count)) | z3.LShR(x, count))
        assert repr(check) == "True", "Unable to simplify z3 assertion {}".format(check)
    print("Verified that z3_rol32 and z3_ror32 are correct")


def reverse_crc32(target_crc, size, polynom=POLY_CRC32_REV):
    """Find all possible inputs of the given size that produce the given CRC32
    """
    assert -0x80000000 <= target_crc <= 0xffffffff
    target_crc &= 0xffffffff

    # Define the input
    input_data = z3.BitVec("input", size * 8)

    # Compute its CRC32
    current_crc = z3.BitVecVal(0xffffffff, 32)
    for input_pos in range(size):
        # NB: use LShR, not >>
        input_byte = z3.Extract(7, 0, z3.LShR(input_data, 8 * input_pos))
        current_crc ^= z3.ZeroExt(24, input_byte)
        for _ in range(8):
            carry = current_crc & 1
            current_crc = z3.LShR(current_crc, 1)
            current_crc ^= polynom * carry
        current_crc = z3.simplify(current_crc)
    current_crc = current_crc ^ 0xffffffff
    current_crc = z3.simplify(current_crc)

    # Craft a solver
    solver = z3.Solver()
    solver.add(current_crc == target_crc)

    # Enumerate all solutions
    solutions = []
    for model in get_solutions(solver):
        i_found = model[input_data].as_long()
        found = b''.join(
            struct.pack('B', (i_found >> (8 * i)) & 0xff)
            for i in range(size))
        if binascii.crc32(found) & 0xffffffff == target_crc:
            solutions.append(found)
        else:
            print("Warning: false-positive '{}' for CRC target 0x{:08x} (buggy z3)".format(
                hexlify_bksl(found), target_crc))
    return solutions


def rev_crc32_4bytes(target_crc, polynom=POLY_CRC32_REV):
    """Reverse a 4-byte CRC32 value without using z3"""
    assert polynom >> 31 == 1
    current_crc = (~target_crc) & 0xffffffff
    for _ in range(32):
        carry = 1 if current_crc & 0x80000000 else 0
        if carry:
            current_crc ^= polynom
        current_crc = (current_crc << 1) | carry
    current_crc ^= 0xffffffff
    return struct.pack('<I', current_crc)


def test_reverse_crc32():
    """Test finding CRC32 inputs"""
    # Find the possible reverses the CRC32 of 4 nul bytes
    crc32_4nul = binascii.crc32(b'\0\0\0\0')
    assert crc32_4nul == 0x2144df1c
    preimages_crc32_4nul = reverse_crc32(crc32_4nul, 4)
    assert preimages_crc32_4nul == [b'\0\0\0\0']
    assert rev_crc32_4bytes(crc32_4nul) == b'\0\0\0\0'

    # 4 FF bytes
    assert reverse_crc32(0xffffffff, 4) == [b'\xff\xff\xff\xff']

    preimages_4_0 = reverse_crc32(0, 4)
    print("CRC32('{}') = 0".format(hexlify_bksl(preimages_4_0[0])))
    assert preimages_4_0 == [b'\x9d\x0a\xd9\x6d']
    assert rev_crc32_4bytes(0) == b'\x9d\x0a\xd9\x6d'

    preimages_5_0 = reverse_crc32(0, 5)
    print("Found {} 5-byte preimages with CRC32 0".format(len(preimages_5_0)))
    assert len(preimages_5_0) == 256
    # Sanity checks
    for preimage in preimages_5_0:
        assert len(preimage) == 5
        assert binascii.crc32(preimage) == 0

    # 1-byte preimages
    onebyte_crc32_values = [binascii.crc32(struct.pack('B', v)) for v in range(256)]
    onebyte_crc32_values.sort()
    print("Checking 1-byte CRC32 preimages...")
    for value in onebyte_crc32_values:
        preimages = reverse_crc32(value, 1)
        # print("- CRC32('{}') = 0x{:08x}".format(
        #     ', '.join(hexlify_bksl(p) for p in preimages), value))
        assert len(preimages) == 1
        for preimage in preimages:
            assert len(preimage) == 1
            assert binascii.crc32(preimage) == value

        # This is slow, so break through to speed up things
        if value >= 0x10000000:
            break


def test_alphanum_guess(verbose=False):
    """Get alphanumetric strings matching a simple password checking algorithm
    from HackingWeek 2015, Reverse 4 challenge
    """
    solver = z3.Solver()
    input_chars = [z3.BitVec("x{}".format(i), 64) for i in range(10)]
    for char_var in input_chars:
        solver.add(z3.Or(
            z3.And(char_var >= 0x30, char_var <= 0x39),
            z3.And(char_var >= 0x41, char_var <= 0x5a),
            z3.And(char_var >= 0x61, char_var <= 0x7a),
        ))

    # Simple algorithm
    value = z3.BitVecVal(0x555555, 64)
    for char_var in input_chars:
        value = value ^ char_var
        value = (value << 7) | z3.LShR(value, 25)
    assert value.size() == 64  # Sanity check
    solver.add(value == 0x7fd5c3fe7ffdf7fe)

    # Restrict the result space more
    solver.add(input_chars[0] == ord('P'))
    solver.add(input_chars[1] == input_chars[3])
    solver.add(input_chars[5] == ord('w'))
    solver.add(input_chars[6] == ord('a'))
    solver.add(input_chars[7] == ord('u'))
    solver.add(input_chars[8] == ord('t'))
    solver.add(input_chars[9] == ord('h'))

    # Find all solutions
    for model in get_solutions(solver):
        if not all(32 <= model[c].as_long() < 127 for c in input_chars):
            print("Skipping invalid solution because of buggy z3")
            continue
        found = ''.join(chr(model[c].as_long()) for c in input_chars)
        if verbose:
            print("Candidate {}".format(repr(found)))
        hexmd5 = hashlib.md5(found.encode('ascii')).hexdigest()
        if hexmd5 == '3efafa3e161a756e6e1711dbceaf9d68':
            print("Found password for simple algorithm: {}.".format(repr(found)))
            return


def test_boolean_add():
    """Prove that x+y = x xor y + 2*(x&y)

    http://www.hackersdelight.org/basics2.pdf
    https://stackoverflow.com/questions/28280041/use-z3-to-prove-identity-of-boolean-arithmetic-formula?rq=1
    """
    x = z3.BitVec('x', 128)  # pylint: disable=invalid-name
    y = z3.BitVec('y', 128)  # pylint: disable=invalid-name
    formulas = (
        x | y == (x ^ y) + (x & y),
        x + y == (x ^ y) + 2 * (x & y),
        x + y == (x | y) + (x & y),
        x + y == 2 * (x | y) - (x ^ y),
        -~x == x + 1,
        ~-x == x - 1,
    )
    for formula in formulas:
        solver = z3.Solver()
        solver.add(z3.Not(formula))
        assert solver.check() == z3.unsat


if __name__ == '__main__':
    test_rotate_operations()
    test_reverse_crc32()
    test_alphanum_guess()
    test_boolean_add()
