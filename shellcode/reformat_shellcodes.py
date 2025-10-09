#!/usr/bin/env python
# -*- coding:UTF-8 -*-
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
"""
Reformat the assembly source code of shellcode by putting the matching
hexadecimal encoding for instructions inside.

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import errno
import re
import os
import os.path
import subprocess
import sys


# subprocess.check_output only exists with Python>=2.7
# Do not fail if it is not found, to skip the test with Python 2.6
if not hasattr(subprocess, 'check_output'):
    sys.stderr.write("This program requires subprocess.check_output.\n")
    sys.exit(0)


def disassemble_shcbin(binfile, objdumpcmd):
    """Extract a disassembly dump of a compiled shellcode binary file
    Return a list of (bytes, instruction) tuples
    """
    # Disassemble the .shcode code section
    cmd = [objdumpcmd, '-d', '-j', '.shcode', binfile]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError:
        print("Unable to disassemble {}, ignoring.".format(binfile))
        return None
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            print("Unable to find {} command.".format(objdumpcmd))
            return None
        raise

    instructions = []
    for line in output.decode('ascii', 'ignore').splitlines():
        matches = re.match(r'\s*[0-9a-f]+:\s*([0-9a-f ]+)(\t.+)?$', line)
        if matches is not None:
            hexby, asm = matches.groups()
            hexby = hexby.strip()
            if asm is not None:
                # Remove auto-generated comment
                asm = asm.split(';')[0].strip()
                asm = asm.split('// #')[0].strip()
                instructions.append((hexby, asm))
            elif instructions:
                # Continued instruction
                lastinstr = instructions[-1]
                instructions[-1] = (lastinstr[0] + ' ' + hexby, lastinstr[1])
    return instructions


def instr_match(asminstr, bininstr):
    """Returns true if the instruction from assembly code matches the one from
    the disassembly listing
    """
    if asminstr == bininstr:
        return True
    asminstr = re.sub(r'\s+', ' ', asminstr)
    bininstr = re.sub(r'\s+', ' ', bininstr)
    asminstr = asminstr.replace(', ', ',')
    bininstr = bininstr.replace(', ', ',')
    if asminstr == bininstr:
        return True

    # ARM Thumb equivalent instructions
    matches = re.match(r'(eor|mov|sub)s(.*)', bininstr)
    if matches is not None:
        bininstr = ''.join(matches.groups())
    if asminstr == bininstr:
        return True

    # ARM group registers
    bininstr = bininstr.replace('r2,r3,r4,r5', 'r2-r5')
    if asminstr == bininstr:
        return True

    # x86 jumps
    for jump in ('call', 'callq',
                 'jae', 'jb', 'je', 'jecxz', 'jmp', 'jne', 'js',
                 'loop'):
        if asminstr.startswith(jump + ' ') and bininstr.startswith(jump + ' '):
            return True

    return False


def reformat_shc_with_file(filename, objdumpcmd):
    """Reformat a shellcode file, from a given filename"""
    if filename.endswith(('.bin', '.exe')):
        asmfile = filename[:-4] + '.S'
        binfile = filename
    elif filename.endswith('.S'):
        asmfile = filename
        for binext in 'bin', 'exe':
            binfile = filename[:-2] + '.' + binext
            if os.path.exists(binfile):
                break
        else:
            sys.stderr.write("Unable to find a binary file for {}\n".format(
                filename))
            return False
    else:
        sys.stderr.write("Unknown file type: {}\n".format(filename))
        return False

    # Read the disassembly listing
    instructions = disassemble_shcbin(binfile, objdumpcmd)
    if instructions is None:
        return True

    # Read the initial assembly file and build a new file
    newasmlines = []
    curinstidx = 0
    bininstrmaxlen = 0
    with open(asmfile, 'r') as fasm:
        for line in fasm:
            strippedline = line.strip()
            # Fall-through lines without instructions
            if strippedline.startswith(('.', '*')):
                newasmlines.append(line)
                continue
            if strippedline.endswith(':'):
                newasmlines.append(line)
                continue
            matches = re.match(r'(/\*[0-9a-f ]+\*/\s*)?([^/]+)(/\*.*\*/\s*)?$',
                               strippedline)
            if matches is None:
                newasmlines.append(line)
                continue

            # Match the instructions with instructions list
            asminstr = matches.group(2).strip()
            hex_instr, disasm_instr = instructions[curinstidx]

            # objdump 2.36 removed the "q" suffix of some instructions
            # https://sourceware.org/git/?p=binutils-gdb.git;a=commitdiff;h=c3f5525ff1aca37c64365fb3493e86cae5472ad2
            if asmfile.endswith("x86_64.S"):
                if disasm_instr.startswith(("callq ", "popq ", "pushq ")):
                    mnemonic, args = disasm_instr.split(" ", 1)
                    disasm_instr = mnemonic[:-1] + " " + args

            # objdump 2.42 use "shr $1,%edx" instead of "shr %edx",
            # otherwise there will be correctness issues when it is extended to support APX NDD
            # https://sourceware.org/git/?p=binutils-gdb.git;a=commit;h=b70a487d5945b13e5ab503be4fc37b964819ec0e
            if asmfile.endswith(("x86_32.S", "x86_64.S")) and disasm_instr == "shr    $1,%edx":
                disasm_instr = "shr    %edx"

            if not instr_match(asminstr, disasm_instr):
                sys.stderr.write("Instructions did not match: {} vs {}\n"
                                 .format(repr(asminstr), repr(disasm_instr)))
                return False

            # Go to next instruction
            curinstidx += 1

            # Prepare a line
            fullline = matches.group(2)
            linecomment = matches.group(3)
            if linecomment:
                fullline += linecomment
            newasmlines.append((hex_instr, fullline))
            if bininstrmaxlen < len(hex_instr):
                bininstrmaxlen = len(hex_instr)

    # Write the assembly file
    with open(asmfile, 'w') as fasm:
        for line in newasmlines:
            if isinstance(line, tuple):
                fasm.write(
                    '    /* ' + line[0] +
                    ' ' * (bininstrmaxlen - len(line[0])) +
                    ' */  ' + line[1] + '\n')
            else:
                fasm.write(line)
    print("Updated {}.".format(asmfile))
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reformat a shellcode source")
    parser.add_argument('file', metavar='FILE', nargs='*',
                        help="files to reformat")
    parser.add_argument('-o', '--objdump', type=str,
                        help="objdump command to use [$OBJDUMP]")

    args = parser.parse_args(argv)

    objdumpcmd = args.objdump or os.environ.get('OBJDUMP') or 'objdump'

    if args.file:
        for filename in args.file:
            if not reformat_shc_with_file(filename, objdumpcmd):
                return 1
    else:
        # By default, analyze all .bin and .exe files but multiarch
        for filename in sorted(os.listdir(os.path.dirname(__file__))):
            if filename.startswith('multiarch_'):
                continue
            if filename.endswith(('.bin', '.exe')):
                if not reformat_shc_with_file(filename, objdumpcmd):
                    return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
