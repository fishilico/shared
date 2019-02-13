# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""
Fix cross-references for x86 Linux's ELF programs compiled in PIC mode

IDA 7.0 (and 7.2) does not support well the following construction:

    .text:08004200          call    $+5
    .text:08004205          pop     ebx
    .text:08004206          lea     ebx, (_GLOBAL_OFFSET_TABLE_ - 8004205h)[ebx]

In the following instructions, ebx is considered as 0x08004205 instead of the
address of _GLOBAL_OFFSET_TABLE_. This breaks all cross-references in
instructions using "offset[ebx]" to compute an address from the GOT.

This construction is commonly found in Linux programs (ELF format) for x86
architecture (32-bit mode) compiled in PIC mode (Position-Independent Code).

This can be fixed by hand, using Ctrl+R and specifying _GLOBAL_OFFSET_TABLE_ as
the base offset. This operation can be automated using op_plain_offset(). This
is what this script is about.

@author: Nicolas Iooss
"""
from idautils import *
from idaapi import *
from idc import *

GOT_ADDR = get_name_ea(BADADDR, '_GLOBAL_OFFSET_TABLE_')
if GOT_ADDR == BADADDR:
    print("Unable to find the GOT!")
else:
    print("Found GOT at %#x" % GOT_ADDR)
    GOT_VAR_NAME = get_name(GOT_ADDR)
    assert GOT_VAR_NAME == '_GLOBAL_OFFSET_TABLE_', "Unexpected GOT name %r" % GOT_VAR_NAME

    HEX_GOT_ADDR = "%#x" % GOT_ADDR

    for segea in Segments():
        # Only process code in .text segment
        if get_segm_name(segea) != '.text':
            continue
        seg_end = get_segm_end(segea)
        assert segea < seg_end
        print(".text from %#x to %#x" % (segea, seg_end))
        for funcea in Functions(segea, seg_end):
            print("Function at %#x (%s)" % (funcea, get_func_name(funcea)))
            for startea, endea in Chunks(funcea):
                for head in Heads(startea, endea):
                    cur_disasm = GetDisasm(head)
                    if '[ebx]' in cur_disasm or '[ebx-' in cur_disasm or '[ebx+' in cur_disasm:
                        if GOT_VAR_NAME in cur_disasm or HEX_GOT_ADDR in cur_disasm:
                            # The instruction already uses the GOT
                            continue

                        # Find out where ebx is used
                        for ope_idx in range(5):
                            ope_str = print_operand(head, ope_idx)
                            if '[ebx' not in ope_str and 'ebx]' not in ope_str:
                                continue
                            print("%#x (%d): %r" % (head, ope_idx, cur_disasm))
                            # Fix the operand!
                            op_plain_offset(head, ope_idx, GOT_ADDR)
