/**
 * This program prints its command line arguments to the standard output
 */
#include "nolibc-syscall-linux.h"

static void _c_start(const void *stack) __attribute__ ((used, noreturn));

static void _c_start(const void *stack)
{
    const unsigned long argc = *(const unsigned long *)stack;
    const char *const *argv = ((const char *const *)stack) + 1;
#ifndef ONLY_ARGV
    const char *const *envp = argv + argc + 1;
#endif

    unsigned long i;
    for (i = 0; i < argc; i++) {
        if (!argv[i]) {
            write_cstring_using_stack(2, "Error: NULL argv before end of array\n");
            exit(1);
        }
        write_cstring_using_stack(1, "argv[");
        write_ulong(1, i);
        write_cstring_using_stack(1, "] = ");
        write_string(1, argv[i]);
        write_char_using_stack(1, '\n');
    }
    /* Show envp too, if compiled without -DONLY_ARGV */
#ifndef ONLY_ARGV
    for (i = 0; envp[i]; i++) {
        write_cstring_using_stack(1, "envp[");
        write_ulong(1, i);
        write_cstring_using_stack(1, "] = ");
        write_string(1, envp[i]);
        write_char_using_stack(1, '\n');
    }
#endif
    exit(0);
}

/**
 * Call _c_start(stack_pointer) with a NULL return address
 */
__asm__ (
"    .text\n"
"    .globl _start\n"
"    .hidden _start\n"

#if defined(__x86_64__)
"    .type _start, @function\n"
"    .align 16\n"
"_start:\n"
"    .cfi_startproc\n"
/* CFI needs rip to be marked as undefined here
 * but clang support this directive only since 3.2 (commit
 * https://github.com/llvm-mirror/llvm/commit/c8fec7e21f5c24303eab8a8592f3b8faff347d86 )
 */
#if !defined(__clang__) || ((__clang_major__ << 16) + __clang_minor__) >= 0x30002
"    .cfi_undefined rip\n"
#endif
/* glibc resets the frame pointer too */
"    xorq %rbp, %rbp\n"
"    movq %rsp, %rdi\n"
"    pushq $0\n"
"    jmp _c_start\n"
"    .cfi_endproc\n"
#elif defined(__i386__)
/* Don't use CFI for _start */
"    .type _start, @function\n"
"_start:\n"
"    xorl %ebp, %ebp\n"
"    pushl %esp\n"
"    pushl $0\n"
"    jmp _c_start\n"
#elif defined(__aarch64__)
"    .type _start, %function\n"
"_start:\n"
"    mov x0, sp\n"
"    mov x29, #0\n" /* fp */
"    mov x30, #0\n" /* lr */
"    b _c_start\n"
#elif defined(__arm__)
"    .type _start, %function\n"
"_start:\n"
"    mov r0, sp\n"
"    mov fp, #0\n"
"    mov lr, #0\n"
"    b _c_start\n"
#else
#    error Unsupported architecture
#endif

/* Defining the size of _start is common for all architecture */
"    .size _start, . - _start\n"
);
