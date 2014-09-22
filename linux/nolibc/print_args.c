/**
 * This program prints its command line arguments to the standard output
 */
#include "nolibc-syscall-linux.h"

static void _c_start(const void *stack) __attribute__((used, noreturn));

static void _c_start(const void *stack)
{
    const unsigned long argc = *(const unsigned long *)stack;
    const char *const *argv = ((const char *const *)stack) + 1;
    /* const char *const *envp = argv + argc + 1; */

    unsigned long i;
    for (i = 0; i < argc; i++) {
        if (!argv[i]) {
            write_string(2, "Error: NULL argv before end of array\n");
            exit(1);
        }
        write_cstring(1, "argv[");
        write_ulong(1, i);
        write_cstring(1, "] = ");
        write_string(1, argv[i]);
        write_cstring(1, "\n");
    }
    exit(0);
}

/**
 * Call _c_start(stack_pointer) with a NULL return address
 */
#if defined __x86_64__ || defined __i386__
__asm__ (
"    .text\n"
"    .globl _start\n"
"    .hidden _start\n"
"    .type _start, @function\n"
"_start:\n"
"    .cfi_startproc\n"
#    if defined __x86_64__
"    movq %rsp, %rdi\n"
"    pushq $0\n"
#    elif defined __i386__
"    pushl %esp\n"
"    pushl $0\n"
#    endif
"    jmp _c_start\n"
"    .cfi_endproc\n"
);
#elif defined __arm__
__asm__ (
"    .text\n"
"    .global _start\n"
"    .hidden _start\n"
"    .type _start, %function\n"
"_start:\n"
"    mov r0, sp\n"
"    mov fp, #0\n"
"    mov lr, #0\n"
"    b _c_start\n"
);
#else
#    error Unsupported architecture
#endif
