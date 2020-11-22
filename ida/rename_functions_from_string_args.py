# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""
Rename functions from strings that are used as arguments in calls of functions
such as __assert_fail:

    void __assert_fail (
        const char *assertion,
        const char *file,
        unsigned int line,
        const char *function);

    void dbg_printf(
        const char *file,
        unsigned int line,
        const char *function,
        const char *fmt, ...);

@author: Nicolas Iooss
"""
from idautils import *
from idaapi import *
from idc import *
import re

for segea in Segments():
    # Only process code in .text segment
    if get_segm_name(segea) != '.text':
        continue
    seg_end = get_segm_end(segea)
    assert segea < seg_end
    for funcea in Functions(segea, seg_end):
        current_function_name = get_func_name(funcea)
        # Find all the possible names of the function, from its calls
        possible_names = set()
        found_function_call = False
        for startea, endea in Chunks(funcea):
            last_lines = []
            for head in Heads(startea, endea):
                cur_disasm = GetDisasm(head)
                last_lines.append(cur_disasm)
                if cur_disasm in ('call    dbg_printf', 'jmp     dbg_printf'):
                    found_function_call = True
                    # print("Function at %#x (%s): %r" % (funcea, current_function_name, cur_disasm))
                    # Find out the arguments of dbg_printf, in edi and edx
                    src_file_path = None
                    src_func_name = None
                    for prev_disasm in last_lines[::-1]:
                        if src_file_path and src_func_name:
                            break
                        m = re.match(r'mov\s+edi, offset (\S+)\s*;', prev_disasm)
                        if src_file_path is None and m:
                            addr = get_name_ea(BADADDR, m.group(1))
                            src_file_path = get_strlit_contents(addr)
                            # print("Found file name sym %r @%#x : %r" % (m.group(1), addr, src_file_path))

                        m = re.match(r'mov\s+edx, offset (\S+)\s*;', prev_disasm)
                        if src_func_name is None and m:
                            addr = get_name_ea(BADADDR, m.group(1))
                            src_func_name = get_strlit_contents(addr)
                            # print("Found func name sym %r @%#x : %r" % (m.group(1), addr, src_file_path))
                    if src_file_path and src_func_name:
                        if src_func_name[0] == '~':
                            src_func_name = 'destructor_' + src_func_name[1:]

                        file_name = src_file_path.rsplit('/', 1)[-1]
                        possible_names.add('%s::%s' % (file_name, src_func_name))

        if not found_function_call:
            pass
        elif not possible_names:
            print("WARNING: unable to find a possible name for function at %#x (%s)" % (funcea, current_function_name))
        elif current_function_name in possible_names:
            pass
        elif len(possible_names) > 1:
            print("WARNING: multiple possible names for %#x (%s) : %s" % (
                funcea, current_function_name, ' '.join(possible_names)))
        else:
            new_name = list(possible_names)[0]
            assert new_name, "Empty new function name"
            print("OK: renaming %#x (%s) to %s" % (funcea, current_function_name, new_name))
            set_name(funcea, new_name)
