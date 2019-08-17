/* Multi-architecture shellcode for Linux
 *
 * Ideas from https://github.com/ixty/xarch_shellcode
 *
 * In order to cross-compile and test ARM with arm-none-eabi toolchain, run:
 *      arm-none-eabi-gcc -Dmain=_start -nostdlib multiarch.S -o multiarch.bin
 *      qemu-arm arm-multiarch.bin
 *  To test ARM Thumb, add -DTEST_ARM_THUMB to the compiler command line.
 */

/* ARM and x86 gas has unfortunately different syntax to declare "main" */
#if defined(__x86_64__) || defined(__i386__)
    /* Mark the stack as not executable */
    .section .note.GNU-stack, "", @progbits
    .section .shcode, "ax", @progbits
    .globl main
    .hidden main
    .type main, @function
#elif defined(__aarch64__) || defined(__arm__)
    .section .note.GNU-stack, "", %progbits
    .section .shcode, "ax", %progbits
    .globl main
    .hidden main
    .type main, %function
#endif

/* Align code */
.balign 4

/* Test ARM Thumb instruction when running on ARM */
main:
#ifdef TEST_ARM_THUMB
    /* ARM: go to Thumb mode */
    .byte 0x01, 0x00, 0x8f, 0xe2    /* add r0, pc, #1 */
    .byte 0x10, 0xff, 0x2f, 0xe1    /* bx r0 */
#endif

    /* ARM:             320114eb    andcc   r1, r1, #-352321536
     * ARM Thumb:       14eb 3201   asrs    r3, r5, #19 ; adds r2, #1
     * ARM64:           320114eb    orr     11, w7, #0x8000001f
     * x86 (32 & 64):   eb14        jmp     0x1a    = _x86_32_or_64
     */
    .byte 0xeb, 0x14, 0x01, 0x32

    /* ARM:             b101e006    tstlt   r1, r6
     * ARM Thumb:       e006        b.n     0x10    = _arm_thumb_trampoline
     * ARM64:           b101e006    adds    x6, x0, #0x78
     */
    .byte 0x06, 0xe0, 0x01, 0xb1

    /* ARM:             ea000000    b       0x8     = _arm_trampoline
     * ARM64:           ea000000    ands    x0, x0, x0
     */
    .byte 0x00, 0x00, 0x00, 0xea

    /* ARM64: b _arm64 */
    .byte ((_arm64 - .) / 4), 0x00, 0x00, 0x14

_arm_trampoline:
    /* ARM: b _arm */
    .byte (_arm - . - 8) / 4, 0x00, 0x00, 0xea

_arm_thumb_trampoline:
    /* ARM Thumb: b _arm_thumb */
    .byte ((_arm_thumb - . - 4) / 2), 0xe0

_x86_32_or_64:
    /* x86_32: 31c0 40 90   xor    %eax,%eax ; inc %eax ; nop
     * x86_64: 31c0 4090    xor    %eax,%eax ; rex xchg %eax,%eax
     */
    .byte 0x31, 0xc0, 0x40, 0x90

    /* x86 (32 & 64): je _x86_64 ; jmp _x86_32 */
    .byte 0x74, (_x86_64 - . - 1)
    .byte 0xeb, (_x86_32 - . - 1)


/* x86_32 payload */
_x86_32:
    .byte 0x31, 0xc0    /* xor %eax, %eax */
    .byte 0x99          /* cltd */
    .byte 0xb2, _x86_32_str_end - _x86_32_str /* mov $(_x86_32_str_end - _x86_32_str), %dl */
    .byte 0x31, 0xdb    /* xor %ebx, %ebx */
    .byte 0x43          /* inc %ebx */
    .byte 0xeb, _x86_32_str - . - 6 /* jmp _x86_64_str_addr */
_x86_32_str_ret:
    .byte 0x59          /* pop %ecx */
    .byte 0xb0, 0x04    /* mov $4, %al */
    .byte 0xcd, 0x80    /* int $0x80 = syscall(eax=__NR_write, ebx=1, ecx=str, edx=len) */

    .byte 0x31, 0xc0    /* xor %eax, %eax */
    .byte 0x89, 0xc3    /* mov %eax, %ebx */
    .byte 0x40          /* inc %eax */
    .byte 0xcd, 0x80    /* int $0x80 = syscall(eax=__NR_exit, ebx=0) */

    .byte 0xe8, _x86_32_str_ret + 256 - . - 4, 0xff, 0xff, 0xff /* call _x86_32_str_ret */
_x86_32_str:
    .ascii "Running on x86_32.\n"
_x86_32_str_end:


/* x86_64 payload */
_x86_64:
    .byte 0x31, 0xc0    /* xor %eax, %eax */
    .byte 0x99          /* cltd */
    .byte 0xb2, _x86_64_str_end - _x86_64_str /* mov $(_x86_64_str_end - _x86_64_str), %dl */
    .byte 0xff, 0xc0    /* inc %eax */
    .byte 0x89, 0xc7    /* mov %eax, %edi */
    .byte 0xeb, _x86_64_str - . - 6 /* jmp _x86_64_str_addr */
_x86_64_str_ret:
    .byte 0x5e          /* pop %rsi */
    .byte 0x0f, 0x05    /* syscall(eax=__NR_write, rdi=1, rsi=str, rdx=len) */

    .byte 0x31, 0xc0    /* xor %eax, %eax */
    .byte 0x89, 0xc7    /* mov %eax, %edi */
    .byte 0xb0, 0x3c    /* mov $60, %al */
    .byte 0x0f, 0x05    /* syscall(eax=__NR_exit, rdi=0) */

    .byte 0xe8, _x86_64_str_ret + 256 - . - 4, 0xff, 0xff, 0xff /* call _x86_64_str_ret */
_x86_64_str:
    .ascii "Running on x86_64.\n"
_x86_64_str_end:


/* ARM payload, aligned on 4 bytes */
    .balign 4, 0xff
_arm:
    .byte 0x01, 0x00, 0xa0, 0xe3    /* mov r0, #1 */
    .byte _arm_str - . - 8, 0x10, 0x8f, 0xe2 /* add r1, pc, #(_arm_str - . - 4) */
    .byte _arm_str_end - _arm_str, 0x20, 0xa0, 0xe3 /*  mov r2, #(_arm_str_end - _arm_str) */
    .byte 0x04, 0x70, 0xa0, 0xe3    /* mov r7, #4 */
    .byte 0x00, 0x00, 0x00, 0xef    /* svc 0 = EABI_syscall(r7=__NR_write, r0=1, r1=str, r2=len) */
    .byte 0x00, 0x00, 0x20, 0xe0    /* eor r0, r0 */
    .byte 0x01, 0x70, 0xa0, 0xe3    /* mov r7, #1 */
    .byte 0x00, 0x00, 0x00, 0xef    /* svc 0 = EABI_syscall(r7=__NR_exit, r0=0) */
_arm_str:
    .ascii "Running on ARM.\n"
_arm_str_end:


/* ARM Thumb payload */
    .balign 4, 0xff
_arm_thumb:
    .byte 0x01, 0x20    /* mov r0, #1 */
    .byte (_arm_thumb_str - . - 2) / 4, 0xa1 /* add r1, pc, #(_arm_thumb_str - . - 2) */
    .byte _arm_thumb_str_end - _arm_thumb_str, 0x22 /* mov r2, #(_arm_thumb_str_end - _arm_thumb_str) */
    .byte 0x04, 0x27    /* mov r7, #4 */
    .byte 0x04, 0xdf    /* svc 4 = syscall(r7=__NR_write, r0=1, r1=str, r2=len) */
    .byte 0x40, 0x40    /* eor r0, r0 */
    .byte 0x01, 0x27    /* mov r7, #1 */
    .byte 0x01, 0xdf    /* svc 1 = syscall(r7=__NR_exit, r0=0) */
_arm_thumb_str:
    .ascii "Running on ARM Thumb.\n"
_arm_thumb_str_end:


/* ARM64 payload */
    .balign 4, 0xff
_arm64:
    .byte 0x20, 0x00, 0x80, 0xd2    /* mov x0, #1 */
    .byte (((_arm64_str - .) & 0x1c000) >> 9) | 0x01, (_arm64_str - .) >> 17, 0x00, 0x90 /* adrp x1, _arm64_str */
    .byte (((_arm64_str - .) & 0x1c) << 3) | 0x01, (_arm64_str - .) >> 5, 0x00, 0x10 /* adr x1, _arm64_str */
    .byte (((_arm64_str_end - _arm64_str) & 7) << 5) | 0x02, (_arm64_str_end - _arm64_str) >> 3, 0x80, 0xd2 /* mov x2, #(_arm64_str_end - _arm64_str) */
    .byte 0x08, 0x08, 0x80, 0xd2    /* mov x8, #64 */
    .byte 0x01, 0x00, 0x00, 0xd4    /* svc #0 = syscall(x8=__NR_write, x0=1, x1=str, x2=len) */
    .byte 0x20, 0x00, 0x01, 0xca    /* eor x0, x1, x1 */
    .byte 0xa8, 0x0b, 0x80, 0xd2    /* mov x8, #93 */
    .byte 0x01, 0x00, 0x00, 0xd4    /* svc #0 = syscall(x8=__NR_exit, x0=0) */
_arm64_str:
    .ascii "Running on ARM64.\n"
_arm64_str_end:

/* Final alignment for the next section */
    .balign 4, 0xff
