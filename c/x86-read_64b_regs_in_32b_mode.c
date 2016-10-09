/**
 * Read 64-bit special registers when running a program in 64-mode on a x86 CPU supporting Long Mode.
 * These registers may contain interesting values.
 *
 * According to amd64 manual, "sysret" instruction will set eip from ecx and rflags from r11.
 * Hence the content of r11 represents the flags at the time of the last syscall.
 *
 * On Linux, here is the output with some comments:
 *  32-bit code segment is 0x23  -- segment 4 of GDT, RPL=3: GDT_ENTRY_DEFAULT_USER32_CS
 *  64-bit code segment is 0x33  -- segment 6 of GDT, RPL=3: GDT_ENTRY_DEFAULT_USER_CS
 *  Specific x86_64 registers:
 *      r8  = 0
 *      r9  = 0
 *      r10 = 0
 *      r11 = 0x246              -- RFLAGS, bits 1=Reserved (set by sysret), 2=PF, 6=ZF, 9=IF
 *      r12 = 0
 *      r13 = 0
 *      r14 = 0
 *      r15 = 0
 * According to syscall and int80 entrypoints, all these registers are set to zero when entering the kernel.
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/entry/entry_64_compat.S
 *
 * On Windows 10, here is the output with some comments:
 *  32-bit code segment is 0x23  -- segment 4 of GDT, RPL=3: user CS for 32-bit code
 *  64-bit code segment is 0x33  -- segment 6 of GDT, RPL=3: user CS for 64-bit code
 *  Specific x86_64 registers:
 *      r8  = 0x2b
 *      r9  = 0x77466d3c         -- Address of last long-to-protected-mode transition (usually into ntdll32).
 *      r10 = 0
 *      r11 = 0x9e6e0
 *      r12 = 0x242000           -- Address of ntdll!_TEB64 (change randomly)
 *      r13 = 0x9fda0            -- CONTEXT32 stored in the TLS containing initial state of the last long-to-protected-mode transition transition.
 *      r14 = 0x9efd0            -- 64-bit stack address.
 *      r15 = 0x52b83560         -- Address of wow64cpu.dll's .rdata exported jump table.
 * Source: https://www.duosecurity.com/static/pdf/wow-64-and-so-can-you.pdf
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __x86_64__
#    error This program needs to be compiled in 32-bit mode
#endif

/**
 * Get the current code segment, which should be 32-bit
 */
static uint32_t get_code32_segment(void)
{
    uint32_t segment;
    uint8_t lar_ok = 0;
    uint32_t access_rights;

    __asm__ (
        "mov %%cs, %[seg] ; larl %[seg], %[ar] ; setz %[ok]"
        : [seg] "=r" (segment), [ar] "=r" (access_rights), [ok] "=q" (lar_ok)
        : : "cc");
    /* Check bits:
     * 0x000800 = Code
     * 0x006000 = DPL 3
     * 0x008000 = present
     * 0x200000 = Long mode (64-bits)
     * 0x400000 = Protected mode (32-bits)
     */
    if (lar_ok && (access_rights & 0x60e800) == 0x40e800) {
        return segment;
    }
    fprintf(stderr, "Runtime error: CS access rights (%#x) tell it is not a 32-bit code segment.\n",
            segment);
    return 0;
}

/**
 * Get the segment defined by the kernel which allows running in 64-bit mode.
 * This is done by reading the GDT (Global Descriptor Table).
 * Return 0 if no such segment was found.
 */
static uint32_t get_code64_segment(void)
{
    uint8_t gdt_descriptor[2 + sizeof(uintptr_t)];
    uint16_t gdt_size;
    uint32_t segment;
    uint8_t lar_ok = 0;
    uint32_t access_rights;

    /* Retrieve the size of the GDT */
    __asm__ ("sgdt %0" : "=m" (gdt_descriptor) : : "memory");
    memcpy(&gdt_size, gdt_descriptor, 2);
    for (segment = 3; segment < gdt_size; segment += 8) {
        /* Load access right associated with the segment */
        __asm__ ("larl %[seg], %[ar] ; setz %[ok]"
            : [ar] "=r" (access_rights), [ok] "=q" (lar_ok)
            : [seg] "r" (segment)
            : "cc", "memory");
        /* Check bits:
         * 0x000800 = Code
         * 0x006000 = DPL 3
         * 0x008000 = present
         * 0x200000 = Long mode (64-bits)
         * 0x400000 = Protected mode (32-bits)
         */
        if (lar_ok && (access_rights & 0x60e800) == 0x20e800) {
            return segment;
        }
    }
    return 0;
}

/**
 * Go into Long Mode and grab the current value of 64-bit registers
 */
static void read_64b_regs(uint32_t seg64, uint64_t regs64[8])
{
    __asm__ (
        /* Push the return address as a far pointer */
        "push   %%cs\n"
        "jmp    1f\n"
        "2:\n"
        /* Push the 64-bit code address as a far pointer */
        "push   %[seg64]\n"
        "jmp    4f\n"
        "5:\n"
        /* Jump to 64-bit code */
        "lret\n"

        /* Set the 64-bit code address up */
        "4:\n"
        "call   5b\n"

        /* Here goes the 64-bit code! */
        ".byte 0x4c, 0x89, 0x07\n"          /* mov %r8, (%rdi) */
        ".byte 0x4c, 0x89, 0x4f, 0x08\n"    /* mov %r9, 0x8(%rdi) */
        ".byte 0x4c, 0x89, 0x57, 0x10\n"    /* mov %r10, 0x10(%rdi) */
        ".byte 0x4c, 0x89, 0x5f, 0x18\n"    /* mov %r11, 0x18(%rdi) */
        ".byte 0x4c, 0x89, 0x67, 0x20\n"    /* mov %r12, 0x20(%rdi) */
        ".byte 0x4c, 0x89, 0x6f, 0x28\n"    /* mov %r13, 0x28(%rdi) */
        ".byte 0x4c, 0x89, 0x77, 0x30\n"    /* mov %r14, 0x30(%rdi) */
        ".byte 0x4c, 0x89, 0x7f, 0x38\n"    /* mov %r15, 0x38(%rdi) */
        ".byte 0xcb\n"                      /* lret */

        /* Set the return address up */
        "1:\n"
        "call   2b\n"
        :
        : [seg64] "r" (seg64), "D" (regs64)
        : "cc", "memory");
}

int main(void)
{
    uint32_t seg32, seg64;
    uint64_t regs64[8] = { 0 };
    int ireg;

    /* Show the current code segment */
    seg32 = get_code32_segment();
    if (!seg32) {
        return 1;
    }
    printf("32-bit code segment is %#x\n", seg32);

    /* Show the long mode code segment */
    seg64 = get_code64_segment();
    if (!seg64) {
        printf("Unable to find a 64-bit code segment. The CPU or the OS may be configured as 32-bit only.\n");
        return 0;
    }
    printf("64-bit code segment is %#x\n", seg64);

    /* Show the regs! */
    read_64b_regs(seg64, regs64);
    printf("Specific x86_64 registers:\n");
    for (ireg = 0; ireg < 8; ireg++) {
        printf("    r%-2u = %#" PRIx64 "\n", ireg + 8, regs64[ireg]);
    }
    return 0;
}
