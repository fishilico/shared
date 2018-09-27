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
"""Decode 8-bit AVR instructions

Links:
* https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=opcodes/avr-dis.c
  AVR disassembler of binutils (used by objdump and gdb)

@author: Nicolas Iooss
@license: MIT
"""
import struct


class IntVal(object):
    """Store an integer value which has a limited number of bits"""
    def __init__(self, value, nbits, signed):
        mask = (1 << nbits) - 1
        assert 0 <= value <= mask
        self.value = value
        self.mask = mask
        self.nbits = nbits
        self.signed = signed

    @property
    def normalized_val(self):
        """Get the normalized value of the integer

        For example, 8-bit signed integer 255 is normalized -1.
        """
        val = self.value
        if self.signed and val >= (1 << (self.nbits - 1)):
            return -((-val) & self.mask)
        return val & self.mask

    def __str__(self):
        val = self.normalized_val
        if -16 < val < 16:
            return str(val)
        return '{:#x}'.format(val)

    def __repr__(self):
        return '<IntVal({:#x}, {}, {})>'.format(
            self.value, self.nbits, 'S' if self.signed else 'U')

    def __eq__(self, other):
        selfval = self.normalized_val
        if isinstance(other, IntVal):
            return selfval == other.normalized_val
        elif isinstance(other, int):
            # Allow comparing to a raw integer
            return selfval == other
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class Int8Bit(IntVal):
    """Represent an 8-bit integer, unsigned by default"""
    # pylint: disable=too-few-public-methods
    def __init__(self, value, signed=False):
        super(Int8Bit, self).__init__(value, 8, signed)


class VarReg(object):
    """A variable composed of several contiguous registers"""
    # pylint: disable=too-few-public-methods
    def __init__(self, firstreg, numregs):
        assert 0 <= firstreg < firstreg + numregs <= 32
        self.firstreg = firstreg
        self.numregs = numregs

    def __str__(self):
        if self.numregs == 1:
            return 'r{}'.format(self.firstreg)
        return ':'.join('r{}'.format(self.firstreg + self.numregs - 1 - i)
                        for i in range(self.numregs))

    def __repr__(self):
        return '<VarReg({})>'.format(str(self))

    def __eq__(self, other):
        if not isinstance(other, VarReg):
            return False
        return (self.firstreg, self.numregs) == (other.firstreg, other.numregs)

    def __ne__(self, other):
        return not self.__eq__(other)


class Reg8Bit(VarReg):
    """An 8-bit register"""
    # pylint: disable=too-few-public-methods
    def __init__(self, reg):
        super(Reg8Bit, self).__init__(reg, 1)


class Reg16Bit(VarReg):
    """A 16-bit register, identified by its low significant byte"""
    # pylint: disable=too-few-public-methods
    def __init__(self, reg):
        super(Reg16Bit, self).__init__(reg, 2)


class SRegBit(object):
    """A bit of SREG register"""
    # pylint: disable=too-few-public-methods
    def __init__(self, flag):
        assert flag in 'CZNVSHTI'
        self.flag = flag

    def __str__(self):
        return self.flag

    def __repr__(self):
        return '<SRegBit({})>'.format(self.flag)

    def __eq__(self, other):
        if isinstance(other, SRegBit):
            return self.flag == other.flags
        elif isinstance(other, str):
            # Allow comparing to a raw string
            return self.flag == other
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class Instruction(object):
    """8-bit AVR instruction"""
    def __init__(self, addr, size, description):
        # Use a string description, or None if __str__ is overloaded
        # Check alignment
        assert (addr % 2) == 0
        assert (size % 2) == 0
        self.addr = addr
        self.size = size
        self.description = description

    def tostr(self, meta):
        """Get a string describing the instruction

        meta can be used to provide some contextual information
        """
        # pylint: disable=unused-argument
        assert self.description is not None
        return self.description

    def show(self, meta):
        """Show the instruction"""
        addr, size = self.addr, self.size
        data = meta.fwmem[addr:addr + size]
        line = '  {:04x}:'.format(addr)
        for i in range(0, size, 2):
            line += ' {:02x}{:02x}'.format(data[i + 1], data[i])
        padding = 15 - 5 * size // 2
        if padding > 0:
            line += ' ' * padding
        line += ' ' + self.tostr(meta)

        comment = meta.comments.get(addr, '')
        if comment:
            padding = 40 - len(line)
            if padding > 0:
                line += ' ' * padding
            line += ' # ' + comment
        print(line)

    def show_merge(self, prev, meta):
        """When having a previous instruction, it may be possible to merge with
        """
        if prev is not None:
            prev.show(meta)
        return self


class BinOpInst(Instruction):
    """Binary operation between a value/reg and a reg, and the carry flag"""
    def __init__(self, addr, size, op, rdest, src, carry):
        # pylint: disable=too-many-arguments
        super(BinOpInst, self).__init__(addr, size, None)
        # Convert r1 back to the register name when used as destination reg
        if op != '?' and rdest == 0:
            rdest = Reg8Bit(1)
        # Transform "x += x" to "x <<= 1, which may have a carry"
        if op == '+' and rdest == src:
            op = '<<'
            src = Int8Bit(1)
        assert not isinstance(src, int)
        self.op = op
        self.rdest = rdest
        self.src = src
        self.carry = carry

    def tostr(self, meta):
        # pylint: disable=too-many-branches,too-many-return-statements
        strsrc = str(self.src)
        if self.carry:
            if self.op in '+-':
                strsrc += '+C'
            elif self.op == '?':
                return 'cmp_carry {}, {}'.format(self.rdest, strsrc)
            elif self.op == '<<' and self.src == 1:
                return 'C:{0} := {0}:C ; << 1'.format(self.rdest)
            elif self.op == '>>' and self.src == 1:
                return '{0}:C := C:{0} ; >> 1'.format(self.rdest)
            else:
                raise Exception("Unknown op with carry '{}'".format(self.op))

        if self.op == '?':
            return 'cmp {}, {}'.format(self.rdest, strsrc)
        elif self.op == '<<' and self.src.value in (1, 2, 3) and not self.carry:
            return '{} *= {}'.format(self.rdest, 1 << self.src.value)
        elif self.op == '>>' and self.src.value in (1, 2, 3) and not self.carry:
            return '{} /= {}'.format(self.rdest, 1 << self.src.value)

        # src may be a pointer to SRAM
        lab = None
        if isinstance(self.rdest, VarReg) and isinstance(self.src, IntVal) and self.src.nbits == 16:
            if self.op == ':':
                lab = meta.sram_labels.get(self.src.value)
            elif self.op == '-':
                lab = meta.sram_labels.get((-self.src.value) & 0xffff)
        if lab is not None:
            strsrc += ' (={})'.format(lab)

        return '{} {}= {}'.format(self.rdest, self.op, strsrc)

    def show_merge(self, prev, meta):
        """Merge with the previous instruction, if possible"""
        # pylint: disable=too-many-branches,too-many-return-statements,too-many-statements
        # Buggy pylint thinks self.rdest is Reg8Bit and self.src Int8Bit
        # pylint: disable=no-member
        if prev is None:
            return self
        if not isinstance(prev, BinOpInst):
            prev.show(meta)
            return self

        # Merge with SEC (set carry)
        if prev.op == ':' and prev.rdest == 'C' and prev.src == 1 and self.carry:
            self.carry = False
            if isinstance(self.src, IntVal):
                self.src.value += 1
            else:
                self.src += '+1'
            self.addr = prev.addr
            self.size += prev.size
            return self

        # Merge two <<  together if no carry
        if prev.op == self.op and self.op in ('<<', '>>') and prev.rdest == self.rdest:
            if not self.carry and not prev.carry:
                prev.size += self.size
                prev.src.value += self.src.value
                return prev

        # Ignore previous if not the same op
        if prev.op != self.op:
            prev.show(meta)
            return self
        if self.op in ('+', '-', '?', '<<', '>>'):
            # Operation with carry, force the previous to have a carry
            if not self.carry:
                prev.show(meta)
                return self
        else:
            assert self.op in '&|^:*'  # If unknown op, add it here
            assert not self.carry  # Never carry

        # Test the destination register
        r1 = prev.rdest
        r2 = self.rdest
        if isinstance(r1, VarReg) and isinstance(r2, VarReg):
            if r1.firstreg + r1.numregs == r2.firstreg:
                if self.op == '<<':
                    if self.src == prev.src:
                        # Do not change the shift count
                        prev.size += self.size
                        prev.rdest.numregs += r2.numregs
                        return prev
                else:
                    if isinstance(prev.src, IntVal) and isinstance(self.src, IntVal):
                        # Concatenate source registers, merge destination integers
                        prev.size += self.size
                        prev.rdest.numregs += r2.numregs
                        value = (self.src.value << prev.src.nbits) | prev.src.value
                        prev.src = IntVal(value, prev.src.nbits + self.src.nbits, prev.src.signed)
                        return prev
                    elif isinstance(prev.src, VarReg) and isinstance(self.src, VarReg):
                        if prev.src.firstreg + prev.src.numregs == self.src.firstreg:
                            # Concatenate source registers, and destination integers
                            prev.size += self.size
                            prev.rdest.numregs += r2.numregs
                            prev.src.numregs += self.src.numregs
                            return prev
                        elif prev.src.numregs == self.src.numregs == 1 and prev.src.firstreg == self.src.firstreg + 1:
                            # Swap bytes
                            prev.size += self.size
                            prev.rdest.numregs += r2.numregs
                            prev.src = 'swap_bytes({}:{})'.format(prev.src, self.src)
                            return prev
                    elif isinstance(self.src, IntVal) and self.src == 0:
                        # Zero-extension
                        prev.size += self.size
                        prev.rdest.numregs += r2.numregs
                        prev.src = '0:' + str(prev.src)
                        return prev
                    elif isinstance(prev.src, IntVal) and prev.src.value == 0:
                        # Left shift by zero-extension in low bytes
                        prev.size += self.size
                        prev.rdest.numregs += r2.numregs
                        prev.src = str(self.src) + (':0' * (prev.src.nbits // 8))
                        return prev
                    elif self.op == '?':
                        # Merge anyway for comparison
                        prev.size += self.size
                        prev.rdest.numregs += r2.numregs
                        prev.src = str(self.src) + ':' + str(prev.src)
                        return prev

            elif self.op == '>>' and r1.firstreg == r2.firstreg + r2.numregs and self.src == prev.src:
                # ">>" reverses the order of registers
                prev.size += self.size
                prev.rdest.firstreg = r2.firstreg
                prev.rdest.numregs += r2.numregs
                return prev

        elif self.op == '?':
            # For compare, the destination can be an integer
            r1 = prev.src
            r2 = self.src
            if isinstance(r1, VarReg) and isinstance(r2, VarReg):
                if r1.firstreg + r1.numregs == r2.firstreg:
                    if isinstance(prev.rdest, IntVal) and isinstance(self.rdest, IntVal):
                        prev.size += self.size
                        prev.src.numregs += r2.numregs
                        value = (self.rdest.value << prev.rdest.nbits) | prev.rdest.value
                        prev.rdest = IntVal(value, prev.rdest.nbits + self.rdest.nbits, prev.rdest.signed)
                        return prev

        prev.show(meta)
        return self


class SetRegInst(BinOpInst):
    """Instruction to set a value to a reg"""
    def __init__(self, addr, size, rdest, value):
        super(SetRegInst, self).__init__(
            addr, size, ':', rdest, value, False)

    def tostr(self, meta):
        # Special case for SREG bits (flags)
        if isinstance(self.rdest, SRegBit) and isinstance(self.src, IntVal):
            if self.src != 0:
                return 'Set({} flag)'.format(self.rdest)
            else:
                return 'Clear({} flag)'.format(self.rdest)
        return super(SetRegInst, self).tostr(meta)


class MulInst(Instruction):
    """Multiplication instruction between two operands to a destination"""
    def __init__(self, addr, size, rdest, op1, op2):
        # pylint: disable=too-many-arguments
        super(MulInst, self).__init__(addr, size, None)
        self.rdest = rdest
        self.op1 = op1
        self.op2 = op2

    def tostr(self, meta):
        return '{} := {} * {}'.format(self.rdest, self.op1, self.op2)


class CondSkipInst(Instruction):
    """Skip next instruction if condition is true"""
    def __init__(self, addr, size, cond, positive):
        super(CondSkipInst, self).__init__(addr, size, None)
        self.cond = cond
        self.positive = positive

    def tostr(self, meta):
        if not self.positive:
            return 'skip_if_not({})'.format(self.cond)
        return 'skip_if({})'.format(self.cond)


class BranchInst(Instruction):
    """Branch instruction (jump, call, conditional jump)

    brinst = branch instruction
    braddr = branch address
    brdesc = description of braddr
    """
    def __init__(self, addr, size, brinst, braddr, brdesc):
        # pylint: disable=too-many-arguments
        super(BranchInst, self).__init__(addr, size, None)
        self.brinst = brinst
        self.braddr = braddr
        self.brdesc = brdesc

    def tostr(self, meta):
        # Branch to register
        if self.braddr is None:
            return ' '.join((self.brinst, self.brdesc))

        if self.braddr == self.addr:
            # Forever loop
            if self.brinst == 'jmp':
                return 'loop_forever_here'
            # While loop
            if self.brinst.endswith(':jmp'):
                if self.brinst.startswith('if_not('):
                    return 'loop_until' + self.brinst[6:-4]
                if self.brinst.startswith('if_'):
                    return 'loop_while' + self.brinst[2:-4]

        return ' '.join((self.brinst, '{:#06x}'.format(self.braddr), self.brdesc))

    def show_merge(self, prev, meta):
        """Merge the branch with the previous instruction

        This is useful for example with a conditional skip instruction
        """
        # pylint: disable=too-many-branches,too-many-statements
        if prev is None:
            return self

        # Merge with conditional skip
        if isinstance(prev, CondSkipInst):
            if prev.positive:
                self.brinst = 'if_not({}):{}'.format(prev.cond, self.brinst)
            else:
                self.brinst = 'if({}):{}'.format(prev.cond, self.brinst)
            self.addr = prev.addr
            self.size += prev.size
            return self

        # Replace 'sbiw 0' with a cmp, when comparing a 16-bit variable to zero
        if isinstance(prev, BinOpInst):
            if prev.op == '-' and not prev.carry and prev.src == 0:
                prev.op = '?'

            # Merge with compare
            if prev.op == '?' and not prev.carry:
                newinst = None
                prevsrc = str(prev.src)
                if self.brinst == 'brcc':
                    newinst = 'if({} >= {}):jmp'.format(prev.rdest, prevsrc)
                elif self.brinst == 'brcs':
                    newinst = 'if({} < {}):jmp'.format(prev.rdest, prevsrc)
                elif self.brinst == 'breq':
                    newinst = 'if({} == {}):jmp'.format(prev.rdest, prevsrc)
                elif self.brinst == 'brne':
                    newinst = 'if({} != {}):jmp'.format(prev.rdest, prevsrc)
                elif self.brinst == 'brge':  # Signed greater or equal
                    newinst = 'if({} >=s {}):jmp'.format(prev.rdest, prevsrc)
                elif self.brinst == 'brlt':  # Signed less than
                    newinst = 'if({} <s {}):jmp'.format(prev.rdest, prevsrc)
                if newinst is not None:
                    self.brinst = newinst
                    self.addr = prev.addr
                    self.size += prev.size
                    return self

            # Merge with 'and x, x'
            if prev.op == '&' and not prev.carry and prev.rdest == prev.src:
                newinst = None
                if self.brinst == 'breq':
                    newinst = 'if_not({}):jmp'.format(prev.rdest)
                elif self.brinst == 'brne':
                    newinst = 'if({}):jmp'.format(prev.rdest)
                if newinst is not None:
                    self.brinst = newinst
                    self.addr = prev.addr
                    self.size += prev.size
                    return self

            # Adapt with sub
            if prev.op == '-':
                newinst = None
                if self.brinst == 'brcc':
                    newinst = 'if({} >= 0):jmp'.format(prev.rdest)
                elif self.brinst == 'brcs':
                    newinst = 'if({} < 0):jmp'.format(prev.rdest)
                if newinst is not None:
                    self.brinst = newinst
                    prev.show(meta)
                    return self

        prev.show(meta)
        return self


class Label(object):
    """Represent a label to a code or data or something else

    Types:
    * C: code
    * D: data
    * J: jumptable
    * P: I/O port
    * R: SRAM
    * c: comment
    * p: padding
    """
    # pylint: disable=too-few-public-methods

    def __init__(self, addr, labtype, name=None):
        assert 0 <= addr < 0x10000
        assert labtype in 'CDJPRcp'
        assert labtype == 'p' or name
        self.addr = addr
        self.labtype = labtype
        self.name = name

    def __repr__(self):
        return 'Label({:#x}, {}, {})'.format(self.addr, repr(self.labtype),
                                             repr(self.name))


class AVR8Meta(object):
    """Store the specific meta-information which help decoding a firmware"""
    # r1 is commonly used as the zero register.
    # Set this to True to simplify code, False to use r1.
    R1_IS_ZERO = True

    def __init__(self, fwmem, labels):
        self.fwmem = fwmem
        # Transform a list of Label objects to a dictionary
        self.comments = {}
        self.ioports = {}
        self.sram_labels = {}
        self.labels = {}
        for lab in labels:
            if lab.labtype == 'c':
                # Comment
                assert lab.addr not in self.comments
                self.comments[lab.addr] = lab.name
            elif lab.labtype == 'R':
                # SRAM label
                assert lab.addr not in self.sram_labels
                self.sram_labels[lab.addr] = lab.name
            elif lab.labtype == 'P':
                # I/O port name
                assert lab.addr not in self.ioports
                assert 0 <= lab.addr < 0x100
                self.ioports[lab.addr] = lab.name
            else:
                assert lab.addr not in self.labels
                self.labels[lab.addr] = lab

    def add_cpu_data(self, ports=None, sram_regs=None, vectors=None):
        """Add CPU-specific data into the labels"""
        # Port numbers
        if ports is not None:
            for port, name in ports.items():
                if port not in self.ioports:
                    self.ioports[port] = name
        # SRAM registers
        if sram_regs is not None:
            for reg, name in sram_regs.items():
                if reg not in self.sram_labels:
                    self.sram_labels[reg] = name
        # Interrupt vectors
        if vectors is not None:
            for vect in range(max(vectors.keys()) + 1):
                addr = vect * 4
                if addr not in self.labels:
                    name = 'int{}'.format(vect)
                    if vect in vectors:
                        name += '_' + vectors[vect]
                    self.labels[addr] = Label(addr, 'C', name)

    def get_port_name(self, port):
        """Return the pseudo-name of an I/O port"""
        name = self.ioports.get(port)
        if name is not None:
            return 'PORT.{}'.format(name)
        return 'PORT.x{:02x}'.format(port)

    def make_branch(self, addr, size, instr, braddr):
        """Create an instruction for a branch instruction to the specified label"""
        lab = self.labels.get(braddr)
        target = '<{}>'.format('??' if lab is None else lab.name)
        return BranchInst(addr, size, instr, braddr, target)

    def get_reg(self, regnum):
        """Get the representation of a register"""
        if self.R1_IS_ZERO and regnum == 1:
            return Int8Bit(0)
        return Reg8Bit(regnum)

    def get_branch_targets(self):
        """Gather every addresses which are used as branch target

        return a dict "addr => is_called"
        """
        curaddr = 0  # Current address
        curtype = 'D'  # Current type (data, code...)
        brdict = {}
        while curaddr < len(self.fwmem):
            lab = self.labels.get(curaddr)
            if lab is not None:
                curtype = lab.labtype

            if curtype == 'C':
                # Instruction
                instr = self.decode_instruction(curaddr)
                if isinstance(instr, BranchInst) and instr.braddr is not None:
                    brdict[instr.braddr] = (instr.brinst == 'call')
                curaddr += instr.size
            elif curtype == 'J':
                # Jump table entry
                entry = struct.unpack('<H', self.fwmem[curaddr:curaddr + 2])[0]
                brdict[entry * 2] = False
                curaddr += 2
            else:
                curaddr += 1
        return brdict

    def show_all(self, start_addr=0):
        """Show all instructions"""
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        orig_r1_is_zero = self.R1_IS_ZERO
        curaddr = start_addr  # Current address
        curtype = 'D'  # Current type (data, code...)
        previous_instr = None
        while curaddr < len(self.fwmem):
            size = 1

            # Show label
            lab = self.labels.get(curaddr)
            if lab is not None:
                if previous_instr is not None:
                    # Flush previous instruction delayed display
                    previous_instr.show(self)
                    previous_instr = None

                if lab.labtype == 'C' and lab.name[0] == '_':
                    print("{}:".format(lab.name))
                elif lab.labtype != 'p':
                    print("\n{}:".format(lab.name))
                curtype = lab.labtype

            if curtype == 'p':
                # Padding
                while curaddr + size < len(self.fwmem):
                    if curaddr + size in self.labels:
                        break
                    size += 1

            elif curtype == 'C':
                # Decode an instruction
                instr = self.decode_instruction(curaddr)
                # Right after a MUL, r1 is no longer 0
                if isinstance(instr, MulInst):
                    self.R1_IS_ZERO = False
                elif orig_r1_is_zero and isinstance(instr, SetRegInst):
                    if instr.rdest == Reg8Bit(1) and instr.src == 0:
                        self.R1_IS_ZERO = True
                size = instr.size
                previous_instr = instr.show_merge(previous_instr, self)

            elif curtype == 'J':
                # Decode a jump table entry
                size = 2
                entry = struct.unpack('<H', self.fwmem[curaddr:curaddr + 2])[0]
                lab = self.labels.get(entry * 2)
                print('  {:04x}: {:04x} addr {:#06x} <{}>'.format(
                    curaddr, entry, entry * 2, '??' if lab is None else lab.name))

            else:
                assert curtype == 'D'
                # Show an hexadecimal dump of the current data
                curaddr_mod16 = curaddr % 16
                curaddr_aln16 = curaddr - curaddr_mod16
                while curaddr_mod16 + size < 16:
                    if curaddr + size >= len(self.fwmem):
                        break
                    if curaddr + size in self.labels:
                        break
                    size += 1

                # Show an hexadecimal dump of the line
                hex_bytes = ''
                asc_bytes = ' ' * curaddr_mod16
                for index in range(16):
                    if index % 2 == 0:
                        hex_bytes += ' '
                    if curaddr_mod16 <= index < curaddr_mod16 + size:
                        byt = self.fwmem[curaddr_aln16 + index]
                        hex_bytes += '{:02x}'.format(byt)
                        asc_bytes += chr(byt) if 32 <= byt < 127 else '.'
                    else:
                        hex_bytes += '  '
                print("  {:04x}: {}  {}".format(curaddr, hex_bytes, asc_bytes))

            assert size > 0
            curaddr += size

        # Restore self.R1_IS_ZERO
        self.R1_IS_ZERO = orig_r1_is_zero

    def decode_instruction(self, addr):
        """Decode an instruction at the given address"""
        # pylint: disable=too-many-branches,too-many-statements
        # pylint: disable=too-many-locals,too-many-return-statements
        opcode = struct.unpack('<H', self.fwmem[addr:addr + 2])[0]

        if opcode == 0:
            return Instruction(addr, 2, 'nop')

        elif opcode & 0xff00 == 0x0100:  # MOVW (Copy Register Word)
            rd = Reg16Bit(((opcode >> 4) & 0xf) * 2)
            rs = Reg16Bit((opcode & 0xf) * 2)
            return SetRegInst(addr, 2, rd, rs)

        elif opcode & 0xfe00 == 0x0200:  # MULS, MULSU, FMUL, FMULS, FMULSU
            raise Exception(
                "Not implemented 'Signed and fractional multiply' {:04x}"
                .format(opcode))

        elif opcode & 0xfc00 == 0x0400:  # CPC (Compare with Carry)
            rd = self.get_reg((opcode >> 4) & 0x1f)
            rs = self.get_reg(((opcode >> 5) & 0x10) | (opcode & 0xf))
            return BinOpInst(addr, 2, '?', rd, rs, True)

        elif opcode & 0xf800 == 0x0800:
            rd = self.get_reg((opcode >> 4) & 0x1f)
            rs = self.get_reg(((opcode >> 5) & 0x10) | (opcode & 0xf))
            operation = (opcode >> 10) & 1
            if operation == 0:  # SBC (Subtract with Carry)
                return BinOpInst(addr, 2, '-', rd, rs, True)
            elif operation == 1:  # ADD
                return BinOpInst(addr, 2, '+', rd, rs, False)

        elif opcode & 0xf000 == 0x1000:
            rd = self.get_reg((opcode >> 4) & 0x1f)
            rs = self.get_reg(((opcode >> 5) & 0x10) | (opcode & 0xf))
            operation = (opcode >> 10) & 3
            if operation == 0:  # CPSE (Compare and Skip if Equal)
                return CondSkipInst(addr, 2, '{} == {}'.format(rd, rs), True)
            elif operation == 1:  # CP (Compare)
                return BinOpInst(addr, 2, '?', rd, rs, False)
            elif operation == 2:  # SUB
                return BinOpInst(addr, 2, '-', rd, rs, False)
            elif operation == 3:  # ADC (Add with Carry)
                # also ROL (Rotate Left) when rd == rs
                return BinOpInst(addr, 2, '+', rd, rs, True)

        elif opcode & 0xf000 == 0x2000:
            rd = self.get_reg((opcode >> 4) & 0x1f)
            rs = self.get_reg(((opcode >> 5) & 0x10) | (opcode & 0xf))
            operation = (opcode >> 10) & 3
            if operation == 0:  # AND
                return BinOpInst(addr, 2, '&', rd, rs, False)
            elif operation == 1:  # EOR (Exclusive Or)
                if rs == rd:
                    return SetRegInst(addr, 2, rs, Int8Bit(0))
                else:
                    return BinOpInst(addr, 2, '^', rd, rs, False)
            elif operation == 2:  # OR
                return BinOpInst(addr, 2, '|', rd, rs, False)
            elif operation == 3:  # MOV
                return SetRegInst(addr, 2, rd, rs)

        elif opcode & 0xf000 == 0x3000:  # CPI (Compare with Immediate)
            rd = self.get_reg(0x10 | ((opcode >> 4) & 0xf))
            k = Int8Bit(((opcode >> 4) & 0xf0) | (opcode & 0xf))
            return BinOpInst(addr, 2, '?', rd, k, False)

        elif opcode & 0xc000 == 0x4000:
            rd = self.get_reg(0x10 | ((opcode >> 4) & 0xf))
            k = Int8Bit(((opcode >> 4) & 0xf0) | (opcode & 0xf))
            operation = (opcode >> 12) & 3
            if operation == 0:  # SBCI (Subtract Immediate with Carry)
                k.signed = True
                return BinOpInst(addr, 2, '-', rd, k, True)
            elif operation == 1:  # SUBI
                k.signed = True
                return BinOpInst(addr, 2, '-', rd, k, False)
            elif operation == 2:  # ORI
                return BinOpInst(addr, 2, '|', rd, k, False)
            elif operation == 3:  # ANDI
                return BinOpInst(addr, 2, '&', rd, k, False)
            raise Exception(
                "Not implemented 'Register-immediate instructions 2' {:04x} {}-{}-x{:02x}"
                .format(opcode, operation, rd, k))

        elif opcode & 0xd000 == 0x8000:  # LDD/STD to Z+k or Y+k (Load/Store Data)
            rd = self.get_reg((opcode >> 4) & 0x1f)
            k = ((opcode >> 8) & 0x20) | ((opcode >> 7) & 0x18) | (opcode & 7)
            reg = 'r29:r28' if opcode & 8 else 'r31:r30'  # Y or Z
            s = (opcode >> 9) & 1
            if k != 0:
                reg = '*({} + 0x{:02x})'.format(reg, k)
            else:
                reg = '*({})'.format(reg)
            if s:
                return Instruction(addr, 2, '{} := {}'.format(reg, rd))
            else:
                return Instruction(addr, 2, '{} := {}'.format(rd, reg))

        elif opcode & 0xfc00 == 0x9000:
            rd = self.get_reg((opcode >> 4) & 0x1f)
            s = opcode & 0x200
            operation = opcode & 0xf
            if operation == 0:
                k = struct.unpack('<H', self.fwmem[addr + 2:addr + 4])[0]
                if k in self.sram_labels:
                    str_k = 'SRAM.{}'.format(self.sram_labels[k])
                else:
                    str_k = 'SRAM.0x{:04x}'.format(k)
                if s:  # STS k, rd (Store Direct to Data Space)
                    return Instruction(addr, 4, '{} := {}'.format(str_k, rd))
                else:  # LDS rd, k (Load Direct from SRAM)
                    return Instruction(addr, 4, '{} := {}'.format(rd, str_k))

            elif operation == 1:
                if s:  # ST Z+, rd
                    return Instruction(addr, 2, '*(r31:r30 ++) := {}'.format(rd))
                else:  # LD rd, Z+
                    return Instruction(addr, 2, '{} := *(r31:r30 ++)'.format(rd))
            elif operation == 2:
                if s:  # ST -Z, rd
                    return Instruction(addr, 2, '*(-- r31:r30) := {}'.format(rd))
                else:  # LD rd, -Z
                    return Instruction(addr, 2, '{} := *(-- r31:r30)'.format(rd))

            elif operation == 4:
                if not s:  # LPM rd, Z (Load Program Memory)
                    return Instruction(addr, 2, '{} := PROG[r31:r30]'.format(rd))
            elif operation == 5:
                if not s:  # LPM rd, Z+
                    return Instruction(addr, 2, '{} := PROG[r31:r30 ++]'.format(rd))

            elif operation == 9:
                if s:  # ST Y+, rd
                    return Instruction(addr, 2, '*(r29:r28 ++) := {}'.format(rd))
                else:  # LD rd, Y+
                    return Instruction(addr, 2, '{} := *(r29:r28 ++)'.format(rd))
            elif operation == 0xa:
                if s:  # ST -Y, rd
                    return Instruction(addr, 2, '*(-- r29:r28) := {}'.format(rd))
                else:  # LD rd, -Y
                    return Instruction(addr, 2, '{} := *(-- r29:r28)'.format(rd))

            elif operation == 0xc:
                if s:  # ST X, rd
                    return Instruction(addr, 2, '*(r27:r26) := {}'.format(rd))
                else:  # LD rd, X
                    return Instruction(addr, 2, '{} := *(r27:r26)'.format(rd))
            elif operation == 0xd:
                if s:  # ST X+, rd
                    return Instruction(addr, 2, '*(r27:r26 ++) := {}'.format(rd))
                else:  # LD rd, X+
                    return Instruction(addr, 2, '{} := *(r27:r26 ++)'.format(rd))
            elif operation == 0xe:
                if s:  # ST -X, rd
                    return Instruction(addr, 2, '*(-- r27:r26) := {}'.format(rd))
                else:  # LD rd, -X
                    return Instruction(addr, 2, '{} := *(-- r27:r26)'.format(rd))

            elif operation == 0xf:
                if rd == 0:
                    rd = 'r1'
                if s:  # PUSH rd
                    return Instruction(addr, 2, 'push {}'.format(rd))
                else:  # POP rd
                    return Instruction(addr, 2, 'pop {}'.format(rd))
            raise Exception(
                "Not implemented 'LD/ST other' {:04x} x{:x}-{}-{}"
                .format(opcode, operation, rd, s))

        elif opcode & 0xfe08 == 0x9400:
            rd = Reg8Bit((opcode >> 4) & 0x1f)
            operation = opcode & 7
            if operation == 0:  # COM rd (One's complement)
                return Instruction(addr, 2, '{} := 0xff - {}'.format(rd, rd))
            elif operation == 1:  # NEG rd
                return Instruction(addr, 2, '{0} := -{0}'.format(rd))
            elif operation == 2:  # SWAP rd (Swap Nibbles)
                return Instruction(addr, 2, 'swap_nibbles {}'.format(rd))
            elif operation == 3:  # INC rd
                return Instruction(addr, 2, '{} ++'.format(rd))
            elif operation == 5:  # ASR rd (Arithmetic Shift Right, bit7 is kept)
                return Instruction(addr, 2, 'asr {}'.format(rd))
            elif operation == 6:  # LSR rd (Logical Shift Right)
                return BinOpInst(addr, 2, '>>', rd, Int8Bit(1), False)
            elif operation == 7:  # ROR rd (Rotate Right through Carry)
                return BinOpInst(addr, 2, '>>', rd, Int8Bit(1), True)
            raise Exception(
                "Not implemented 1-operand instructions' {:04x} {}-{}"
                .format(opcode, operation, rd))

        elif opcode & 0xff0f == 0x9408:
            flagnum = (opcode >> 4) & 7
            bval = (opcode >> 7) & 1
            # flagnum = 0: CLC/SEC (carry)
            # flagnum = 6: CLT/SET (T in SREG)
            # flagnum = 7: CLI/SEI (interrupt)
            flags = 'CZNVSHTI'
            return SetRegInst(addr, 2, SRegBit(flags[flagnum]), Int8Bit(0 if bval else 1))
        elif opcode & 0xff0f == 0x9508:
            operation = (opcode >> 4) & 0xf
            if operation == 0:  # RET
                return Instruction(addr, 2, 'ret')
            elif operation == 1:  # RETI
                return Instruction(addr, 2, 'ret_int')
            elif operation == 0xa:  # WDR (Watchdog Reset)
                return Instruction(addr, 2, 'watchdog_reset')
            elif operation == 0xe:  # SPM (Store Program Memory)
                return Instruction(addr, 2, 'store_program_memory')
            raise Exception(
                "Not implemented 'Misc instructions (RET, RETI, SLEEP, etc.)' {:04x} x{:02x}"
                .format(opcode, operation))

        elif opcode & 0xfeef == 0x9409:
            c = (opcode >> 8) & 1
            operation = (opcode >> 4) & 1
            if operation == 0:  # IJMP/ICALL (Indirect jump/call to Z)
                return BranchInst(addr, 2, 'icall' if c else 'ijmp', None, 'r31:r30')
            raise Exception(
                "Not implemented 'Indirect jump/call to Z or EIND:Z' {:04x}"
                .format(opcode))

        elif opcode & 0xfe0f == 0x940a:  # DEC
            rd = Reg8Bit((opcode >> 4) & 0x1f)
            return Instruction(addr, 2, '{} --'.format(rd))

        elif opcode & 0xfe0c == 0x940c:  # JMP/CALL (absolute jump/call)
            c = opcode & 2
            k = ((opcode >> 3) & 0x3e) | (opcode & 1)
            if k:
                raise Exception("JMP/CALL with too big address not yet implemented")
            braddr = struct.unpack('<H', self.fwmem[addr + 2:addr + 4])[0] << 1
            return self.make_branch(addr, 4, 'call' if c else 'jmp', braddr)

        elif opcode & 0xfe00 == 0x9600:
            k = Int8Bit(((opcode >> 2) & 0x30) | (opcode & 0xf), True)
            rp_id = (opcode >> 4) & 3  # register pair (W, X, Y, Z)
            operation = (opcode >> 8) & 1
            rp = Reg16Bit(24 + 2 * rp_id)
            assert 0 <= k.value < 128  # Better play it safe with value size
            if operation == 0:  # ADIW
                return BinOpInst(addr, 2, '+', rp, k, False)
            elif operation == 1:  # SBIW
                return BinOpInst(addr, 2, '-', rp, k, False)

        elif opcode & 0xfc00 == 0x9800:
            bitnum = opcode & 7
            port = self.get_port_name((opcode >> 3) & 0x1f)
            bval = (opcode >> 9) & 1
            operation = (opcode >> 8) & 1
            bitdesc = 'bit({}, {})'.format(port, bitnum)
            if operation == 0:
                if bval:  # SBI
                    return Instruction(addr, 2, 'set_' + bitdesc)
                else:  # CBI (Clear Bit in I/O Register)
                    return Instruction(addr, 2, 'clear_' + bitdesc)
            elif operation == 1:
                # bval = 0: SBIC (Skip if Bit is Cleared)
                # bval = 1: SBIS (Skip if Bit is Set)
                return CondSkipInst(addr, 2, bitdesc, bval != 0)

        elif opcode & 0xfc00 == 0x9c00:  # MUL (Multiply Unsigned)
            rd = self.get_reg((opcode >> 4) & 0x1f)
            rs = self.get_reg(((opcode >> 5) & 0x10) | (opcode & 0xf))
            return MulInst(addr, 2, Reg16Bit(0), rd, rs)

        elif opcode & 0xf000 == 0xb000:
            rd = self.get_reg((opcode >> 4) & 0x1f)
            port = self.get_port_name(((opcode >> 5) & 0x30) | (opcode & 0xf))
            s = opcode & 0x800
            if s:  # Store is OUT
                return Instruction(addr, 2, '{} := {}'.format(port, rd))
            else:  # Load is IN
                return Instruction(addr, 2, '{} := {}'.format(rd, port))

        elif opcode & 0xe000 == 0xc000:  # RJMP/RCALL (relative jump/call)
            c = opcode & 0x1000
            if (opcode & 0xfff) == 0:
                return Instruction(addr, 2, 'nop')
            braddr = addr + 2 + 2 * (opcode & 0xfff)
            if opcode & 0x800:
                braddr -= 0x2000
            return self.make_branch(addr, 2, 'call' if c else 'jmp', braddr)

        elif opcode & 0xf000 == 0xe000:  # LDI (Load Immediate)
            rd = self.get_reg(0x10 | ((opcode >> 4) & 0xf))
            k = Int8Bit(((opcode >> 4) & 0xf0) | (opcode & 0xf))
            return SetRegInst(addr, 2, rd, k)

        elif opcode & 0xf800 == 0xf000:
            breg = opcode & 7
            braddr = addr + 2 + ((opcode >> 2) & 0xfe)
            bval = (opcode >> 10) & 1
            if opcode & 0x200:
                braddr -= 0x100
            instr = None
            if breg == 0:  # BRCC/BRCS (Branch if Carry Clear/Set)
                instr = 'brcc' if bval else 'brcs'
            elif breg == 1:  # BRNE/BREQ (Branch if (Not) Equal)
                instr = 'brne' if bval else 'breq'
            elif breg == 2:  # BRPL/BRMI (Branch if Plus/Minus)
                instr = 'brpl' if bval else 'brmi'
            elif breg == 4:  # BRGE/BRLT (Branch if Greater or Equal, Signed / Less Than)
                instr = 'brge' if bval else 'brlt'
            elif breg == 6:  # BRTC (Branch if T Flag Cleared)
                instr = 'brtc' if bval else None
            if instr is None:
                raise Exception(
                    "Not implemented 'Conditional branch on status register bit' {:04x} {}-{}-x{:04x}"
                    .format(opcode, breg, bval, braddr))
            return self.make_branch(addr, 2, instr, braddr)

        elif opcode & 0xfc08 == 0xf800:
            bitnum = opcode & 7
            rd = self.get_reg((opcode >> 4) & 0x1f)
            if opcode & 0x200:  # BST (Bit Store to T Flag)
                return Instruction(addr, 2, 'T := bit({}, {})'.format(rd, bitnum))
            else:  # BLD (Bit Load from the T Flag)
                return Instruction(addr, 2, 'bit({}, {}) := T'.format(rd, bitnum))
            raise Exception(
                "Not implemented 'BLD/BST register bit to STATUS.T' {:04x}"
                .format(opcode))

        elif opcode & 0xfc08 == 0xfc00:
            bitnum = opcode & 7
            rd = self.get_reg((opcode >> 4) & 0x1f)
            bval = (opcode >> 9) & 1
            bitdesc = 'bit({}, {})'.format(rd, bitnum)
            # bval = 0: SBRC (Skip if Bit in Register is Cleared)
            # bval = 1: SBRS (Skip if Bit in Register is Set)
            return CondSkipInst(addr, 2, bitdesc, bval != 0)

        else:
            raise Exception("Unknow instruction class of {:04x}".format(opcode))
        raise Exception("Oops, missing a return somewhere")
