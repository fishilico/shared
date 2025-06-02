/**
 * Analyze the buffer used by setjmp, sigsetjmp, longjmp, siglongjmp
 *
 * Documentation:
 * * http://man7.org/linux/man-pages/man3/setjmp.3.html
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for sigsetjmp */
#endif

#include <assert.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Recognize the used C library using the first instruction of setjmp or sigsetjmp */
struct known_libc {
    const char *os_name;
    const char *libc_name;
    const char *arch_name;
    size_t setjmp_code_len;
    const uint8_t *setjmp_code;
    size_t sigsetjmp_code_len;
    const uint8_t *sigsetjmp_code;
    /* Description of the registers in jmp_buf */
    unsigned long jmp_buf_count;
    const char *const *jmp_buf_desc;
    /* Description of the registers in sigjmp_buf */
    unsigned long sigjmp_buf_count;
    const char *const *sigjmp_buf_desc;
    /* Optional functions to unmangle a value */
    uintptr_t (*unmangle_jmp_buf_value)(unsigned long idx, uintptr_t value);
    uintptr_t (*unmangle_sigjmp_buf_value)(unsigned long idx, uintptr_t value);
};
static const struct known_libc *g_current_libc;

#define DEFINE_KNOWN_LIBC(os_name, libc_name, arch_name, setjmp_code, sigsetjmp_code, jmp_buf_desc, sigjmp_buf_desc, unmangle_jmp_buf_value, unmangle_sigjmp_buf_value) \
    { \
        os_name, \
        libc_name, \
        arch_name, \
        sizeof(setjmp_code) - 1, \
        (const uint8_t *)setjmp_code, \
        sizeof(sigsetjmp_code) - 1, \
        (const uint8_t *)sigsetjmp_code, \
        (unsigned long)(sizeof(jmp_buf_desc) / sizeof(jmp_buf_desc[0])), \
        jmp_buf_desc, \
        (unsigned long)(sizeof(sigjmp_buf_desc) / sizeof(sigjmp_buf_desc[0])), \
        sigjmp_buf_desc, \
        unmangle_jmp_buf_value, \
        unmangle_sigjmp_buf_value, \
    }

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
    /* Windows does not have sigsetjmp, and setjmp is a macro */
#    define setjmp_symbol _setjmp
#else
#    define setjmp_symbol setjmp
#    if defined(sigsetjmp)
        /* glibc defines sigsetjmp as __sigsetjmp */
#        define sigsetjmp_symbol __sigsetjmp
#    else
#        define sigsetjmp_symbol sigsetjmp
#    endif
#endif

/* Implement glibc's PTR_MANGLE from */
static uintptr_t glibc_unmangle_value(unsigned long idx, uintptr_t value)
{
#if defined(__aarch64__) && defined(sigsetjmp_symbol)
    uint64_t sigsetjmp_addr, got_addr, guard_offset, p_guard_addr;

    /* Unmangle pc, sp */
    if (idx == 11 || idx == 13) {
        /* Extract the address offset to pointer_chk_guard from sigsetjmp code */
        sigsetjmp_addr = (uint64_t)sigsetjmp_symbol;
        /* Decode "f0000942  adrp x2, 12b000" */
        got_addr = ((sigsetjmp_addr + 0x18) & ~0xfff) +
            ((g_current_libc->sigsetjmp_code[0x17] & 0x60) << (12 - 5)) +
            ((g_current_libc->sigsetjmp_code[0x14] & 0xe0) << (12 + 2 - 5)) +
            (g_current_libc->sigsetjmp_code[0x15] << (12 + 5)) +
            (g_current_libc->sigsetjmp_code[0x16] << (12 + 13));
        /* Decode:
         *   f9470442  ldr x2, [x2, #3592]
         *   f9471042  ldr x2, [x2, #3616]
         * Format: 1xx1 1001 01ii iiii iiii iinn nnnt tttt  -  ldr Rt ADDR_UIMM12
         * The immediate is multiplied by 8
         */
        guard_offset = ((g_current_libc->sigsetjmp_code[0x19] & 0xfc) << (3 - 2)) +
            ((g_current_libc->sigsetjmp_code[0x1a] & 0x3f) << (3 + 6));
        p_guard_addr = got_addr + guard_offset;
        value = value ^ **(const uint64_t *const *)p_guard_addr;
    }
#elif defined(__arm__) && defined(sigsetjmp_symbol)
    uint32_t sigsetjmp_addr, got_offset_in_sigsetjmp, got_addr, guard_offset_in_sigsetjmp, p_guard_addr;

    /* Unmangle sp, pc */
    if (idx == 0 || idx == 1) {
        /* Extract the pointer to pointer_chk_guard from sigsetjmp code */
        sigsetjmp_addr = (uint32_t)sigsetjmp_symbol;
        got_offset_in_sigsetjmp = 8 + g_current_libc->sigsetjmp_code[0];
        got_offset_in_sigsetjmp += ((uint32_t)g_current_libc->sigsetjmp_code[1] & 0x0f) << 8;
        got_addr = sigsetjmp_addr + 0x10 + *(const uint32_t *)(sigsetjmp_addr + got_offset_in_sigsetjmp);
        guard_offset_in_sigsetjmp = 0xc + g_current_libc->sigsetjmp_code[4];
        guard_offset_in_sigsetjmp += ((uint32_t)g_current_libc->sigsetjmp_code[5] & 0x0f) << 8;
        p_guard_addr = got_addr + *(const uint32_t *)(sigsetjmp_addr + guard_offset_in_sigsetjmp);
        value = value ^ **(const uint32_t *const *)p_guard_addr;
    }
#elif defined(__x86_64__)
    uint64_t pointer_chk_guard;

    /* Unmangle rbp, rsp or rip
     * https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86_64/sysdep.h;hb=refs/tags/glibc-2.30#l405
     */
    if (idx == 1 || idx == 6 || idx == 7) {
        __asm__ volatile ("movq %%fs:0x30, %0" : "=r" (pointer_chk_guard));
        value = ((value >> 0x11) | (value << (64 - 0x11))) ^ pointer_chk_guard;
    }
#elif defined(__i386__)
    uint32_t pointer_chk_guard;

    /* Unmangle esp or eip */
    if (idx == 4 || idx == 5) {
        __asm__ volatile ("movl %%gs:0x18, %0" : "=r" (pointer_chk_guard));
        value = ((value >> 9) | (value << (32 - 9))) ^ pointer_chk_guard;
    }
#else
    (void)idx; /* Mark the variable as used */
#endif
    return value;
}

static const char *const no_sigjmp_buf_desc[1] = { NULL };

static const char *const linux_glibc_aarch64_sigjmp_buf_desc[24] = {
    /* 0x00 */ "x19",
    /* 0x08 */ "x20",
    /* 0x10 */ "x21",
    /* 0x18 */ "x22",
    /* 0x20 */ "x23",
    /* 0x28 */ "x24",
    /* 0x30 */ "x25",
    /* 0x38 */ "x26",
    /* 0x40 */ "x27",
    /* 0x48 */ "x28",
    /* 0x50 */ "x29",
    /* 0x58 */ "pc ^ __pointer_chk_guard_local (pc is accessed via x30=lr)",
    /* 0x60 */ NULL,
    /* 0x68 */ "sp ^ __pointer_chk_guard_local",
    /* 0x70 */ "d8",
    /* 0x78 */ "d9",
    /* 0x80 */ "d10",
    /* 0x88 */ "d11",
    /* 0x90 */ "d12",
    /* 0x98 */ "d13",
    /* 0xa0 */ "d14",
    /* 0xa8 */ "d15",
    /* 0xb0 */ "1 if saved signal mask is present",
    /* 0xb8 */ "saved signal mask",
};

static const char *const linux_glibc_arm_sigjmp_buf_desc[67] = {
    /* 0x00 */ "sp ^ __pointer_chk_guard_local",
    /* 0x04 */ "pc ^ __pointer_chk_guard_local (pc is accessed via lr)",
    /* 0x08 */ "r4 = v1",
    /* 0x0c */ "r5 = v2",
    /* 0x10 */ "r6 = v3",
    /* 0x14 */ "r7 = v4",
    /* 0x18 */ "r8 = v5",
    /* 0x1c */ "r9 = v6",
    /* 0x20 */ "r10 = sl",
    /* 0x24 */ "r11 = fp",
    /* 0x28 */ "d8 (VFP)", "d8 (VFP)",
    /* 0x30 */ "d9 (VFP)", "d9 (VFP)",
    /* 0x38 */ "d10 (VFP)", "d10 (VFP)",
    /* 0x40 */ "d11 (VFP)", "d11 (VFP)",
    /* 0x48 */ "d12 (VFP)", "d12 (VFP)",
    /* 0x50 */ "d13 (VFP)", "d13 (VFP)",
    /* 0x58 */ "d14 (VFP)", "d14 (VFP)",
    /* 0x60 */ "d15 (VFP)", "d15 (VFP)",
    /* 0x68 */ "f2 (iWMMXt)", "f2 (iWMMXt)",
    /* 0x70 */ "f3 (iWMMXt)", "f3 (iWMMXt)",
    /* 0x78 */ "f4 (iWMMXt)", "f4 (iWMMXt)",
    /* 0x80 */ "f5 (iWMMXt)", "f5 (iWMMXt)",
    /* 0x88 */ "f6 (iWMMXt)", "f6 (iWMMXt)",
    /* 0x90 */ "f7 (iWMMXt)", "f7 (iWMMXt)",
    /* 0x98 */ NULL, NULL,
    /* 0xa0 */ NULL, NULL, NULL, NULL,
    /* 0xb0 */ NULL, NULL, NULL, NULL,
    /* 0xc0 */ NULL, NULL, NULL, NULL,
    /* 0xd0 */ NULL, NULL, NULL, NULL,
    /* 0xe0 */ NULL, NULL, NULL, NULL,
    /* 0xf0 */ NULL, NULL, NULL, NULL,
    /* 0x100 */ "1 if saved signal mask is present",
    /* 0x104 */ "saved signal mask", "saved signal mask",
};

static const char *const linux_glibc_x86_32_sigjmp_buf_desc[12] = {
    /* 0x00 */ "ebx",
    /* 0x04 */ "esi",
    /* 0x08 */ "edi",
    /* 0x0c */ "ebp",
    /* 0x10 */ "ROL(esp ^ gs:0x18, 9)",
    /* 0x14 */ "ROL(eip ^ gs:0x18, 9)",
    /* 0x18 */ "1 if saved signal mask is present", /* int __mask_was_saved */
    /* 0x1c */ "saved signal mask (low, only with sigjmp)", /* __sigset_t __saved_mask */
    /* 0x20 */ "saved signal mask (high, only with sigjmp)",
    /* 0x24 */ NULL,
    /* 0x28 */ "SSP (Shadow SSP)",  /* With CET only (at gs:0x20), read with "rdsspd %rcx", set with "incsspd %rbx" */
};

static const char *const linux_glibc_x86_64_sigjmp_buf_desc[12] = {
    /* 0x00 */ "rbx",
    /* 0x08 */ "ROL(rbp ^ fs:0x30, 0x11)",
    /* 0x10 */ "r12",
    /* 0x18 */ "r13",
    /* 0x20 */ "r14",
    /* 0x28 */ "r15",
    /* 0x30 */ "ROL(rsp ^ fs:0x30, 0x11)",
    /* 0x38 */ "ROL(rip ^ fs:0x30, 0x11)",
    /* 0x40 */ "1 if saved signal mask is present",
    /* 0x48 */ "saved signal mask (only with sigjmp)",
    /* 0x50 */ NULL,
    /* 0x58 */ "SSP (Shadow SSP)",  /* With CET only (at fs:0x48), read with "rdsspq %rax", set with "incsspq %rbx" */
};

static const char *const linux_musl_x86_64_jmp_buf_desc[8] = {
    /* 0x00 */ "rbx",
    /* 0x08 */ "rbp",
    /* 0x10 */ "r12",
    /* 0x18 */ "r13",
    /* 0x20 */ "r14",
    /* 0x28 */ "r15",
    /* 0x30 */ "rsp",
    /* 0x38 */ "rip",
};

static const char *const linux_musl_x86_64_sigjmp_buf_desc[11] = {
    /* 0x00 */ "rdi (first argument of setjmp())",
    /* 0x08 */ "rbp",
    /* 0x10 */ "r12",
    /* 0x18 */ "r13",
    /* 0x20 */ "r14",
    /* 0x28 */ "r15",
    /* 0x30 */ "rsp",
    /* 0x38 */ "rip in sigsetjmp", /* sigsetjmp() calls setjmp() */
    /* 0x40 */ "rip",
    /* 0x48 */ "0",
    /* 0x50 */ "rbx",
};

static const char *const windows_x86_32_jmp_buf_desc[16] = {
    /* 0x00 */ "ebp",
    /* 0x04 */ "ebx",
    /* 0x08 */ "edi",
    /* 0x0c */ "esi",
    /* 0x10 */ "esp",
    /* 0x14 */ "eip",
    /* 0x18 */ "Registration",
    /* 0x1c */ "TryLevel",
    /* 0x20 */ "Cookie",
    /* 0x24 */ "UnwindFunc",
    /* 0x28 */ "UnwindData[0]",
    /* 0x2c */ "UnwindData[1]",
    /* 0x30 */ "UnwindData[2]",
    /* 0x34 */ "UnwindData[3]",
    /* 0x38 */ "UnwindData[4]",
    /* 0x3c */ "UnwindData[5]",
};

static const char *const windows_x86_64_jmp_buf_desc[32] = {
    /* 0x00 */ "frame", /* from parameter rdx */
    /* 0x08 */ "rbx",
    /* 0x10 */ "rsp",
    /* 0x18 */ "rbp",
    /* 0x20 */ "rsi",
    /* 0x28 */ "rdi",
    /* 0x30 */ "r12",
    /* 0x38 */ "r13",
    /* 0x40 */ "r14",
    /* 0x48 */ "r15",
    /* 0x50 */ "rip",
    /* 0x58 */ "MXCSR, FPU Control Word", /* padding for MinGW, stmxcsr 0x58(%rcx);fnstcw 0x5c(%rcx) for Windows */
    /* 0x60 */ "xmm6", "xmm6",
    /* 0x70 */ "xmm7", "xmm7",
    /* 0x80 */ "xmm8", "xmm8",
    /* 0x90 */ "xmm9", "xmm9",
    /* 0xa0 */ "xmm10", "xmm10",
    /* 0xb0 */ "xmm11", "xmm11",
    /* 0xc0 */ "xmm12", "xmm12",
    /* 0xd0 */ "xmm13", "xmm13",
    /* 0xe0 */ "xmm14", "xmm14",
    /* 0xf0 */ "xmm15", "xmm15",
};

static const struct known_libc libc_database[] = {
    /* https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/setjmp.S;hb=refs/tags/glibc-2.30:
     * * Arch Linux with aarch64-linux-gnu-glibc 2.30
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc (guard loader f0000942;f9471042)", "ARM64 (aarch64)",
        "!\0\x80\xd2\x07\0\0\x14",
        "\x13P\0\xa9\x15X\x01\xa9\x17`\x02\xa9\x19h\x03\xa9\x1bp\x04\xa9\x42\t\0\xf0\x42\x10G\xf9\x43\0@\xf9\xc4\x03\x03\xca\x1d\x10\x05\xa9\x08$\x07m\n,\x08m\x0c\x34\tm\x0e<\nm\xe4\x03\0\x91\x42\t\0\xf0\x42\x10G\xf9\x43\0@\xf9\x85\0\x03\xca\x05\x34\0\xf9",
        linux_glibc_aarch64_sigjmp_buf_desc, linux_glibc_aarch64_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),
    /* This has been seen on:
     * * Debian 10 with libc6:arm64 2.28-10
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc (guard loader b00009c2;f9470442)", "ARM64 (aarch64)",
        "!\0\x80\xd2\x07\0\0\x14",
        "\x13P\0\xa9\x15X\x01\xa9\x17`\x02\xa9\x19h\x03\xa9\x1bp\x04\xa9\xc2\t\0\xb0\x42\x04G\xf9\x43\0@\xf9\xc4\x03\x03\xca\x1d\x10\x05\xa9\x08$\x07m\n,\x08m\x0c\x34\tm\x0e<\nm\xe4\x03\0\x91\xc2\t\0\xb0\x42\x04G\xf9\x43\0@\xf9\x85\0\x03\xca\x05\x34\0\xf9",
        linux_glibc_aarch64_sigjmp_buf_desc, linux_glibc_aarch64_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),

    /* https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/arm/setjmp.S;hb=refs/tags/glibc-2.30 */
    DEFINE_KNOWN_LIBC("Linux", "glibc", "ARM-HF",
        "\x01\x10\xa0\xe3\xcd\xff\xff\xea",
        "d\xc0\x9f\xe5\x64 \x9f\xe5\x0f\xc0\x8c\xe0\x02\xc0\x9c\xe7\0 \x9c\xe5\0\xc0\xa0\xe1\r0\xa0\xe1\x02\x30#\xe0\x04\x30\x8c\xe4\x02\x30.\xe0\x04\x30\x8c\xe4\xf0\x0f\xac\xe8<0\x9f\xe5< \x9f\xe5\x0f\x30\x83\xe0\x02\x30\x93\xe7@ \x93\xe5\x10\x8b\xac\xec\x02\x0c\x12\xe3\x05\0\0\n\x02\xa1\xec\xec\x02\xb1\xec\xec\x02\xc1\xec\xec\x02\xd1\xec\xec\x02\xe1\xec\xec\x02\xf1\xec\xec\x03\0\0\xea",
        linux_glibc_arm_sigjmp_buf_desc, linux_glibc_arm_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),

    DEFINE_KNOWN_LIBC("Linux", "glibc", "ARM-HF Thumb",
        "O\xf0\x01\x01\xff\xf7\xbc\xbf",
        "", /* The first instructions are "movw ip, #... ; movt ip, #..." with a variable value */
        linux_glibc_arm_sigjmp_buf_desc, linux_glibc_arm_sigjmp_buf_desc,
        NULL, NULL),

    /* glibc with __SOFTFP__ */
    DEFINE_KNOWN_LIBC("Linux", "glibc", "ARM-EL SoftFP",
        "\x01\x10\xa0\xe3\xcd\xff\xff\xea",
        "l\xc0\x9f\xe5l \x9f\xe5\x0f\xc0\x8c\xe0\x02\xc0\x9c\xe7\0 \x9c\xe5\0\xc0\xa0\xe1\r0\xa0\xe1\x02\x30#\xe0\x04\x30\x8c\xe4\x02\x30.\xe0\x04\x30\x8c\xe4\xf0\x0f\xac\xe8\x44\x30\x9f\xe5\x44 \x9f\xe5\x0f\x30\x83\xe0\x02\x30\x93\xe7@ \x93\xe5@\0\x12\xe3\0\0\0\n\x10\x8b\xac\xec\x02\x0c\x12\xe3\x05\0\0\n\x02\xa1\xec\xec\x02\xb1\xec\xec\x02\xc1\xec\xec\x02\xd1\xec\xec\x02\xe1\xec\xec\x02\xf1\xec\xec\x03\0\0\xea",
        linux_glibc_arm_sigjmp_buf_desc, linux_glibc_arm_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),

    /* https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/i386/setjmp.S;hb=refs/tags/glibc-2.30
     * This has been seen on:
     * * Debian 8 with libc6:i386 2.19-18+deb8u10
     * * Debian 9 with libc6:i386 2.24-11+deb9u4
     * * Debian 10 with libc6:i386 2.28-10
     * * Debian 11 with libc6:i386 2.29-3
     * * Gentoo with sys-libs/glibc 2.29-r2
     * * Ubuntu 12.04 with libc6:i386 2.15-0ubuntu10.18
     * * Ubuntu 14.04 with libc6:i386 2.19-0ubuntu6.15
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc", "x86_32",
        "\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$e3\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0cj\x01\xfft$\x08\xe8",
        "\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$e3\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0c\xe9",
        linux_glibc_x86_32_sigjmp_buf_desc, linux_glibc_x86_32_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),
    /* There is a NOP, written in glibc as:
     * LIBC_PROBE (setjmp, 3, 4@%eax, -4@SIGMSK(%esp), 4@%ecx)
     * This has been seen on:
     * * Fedora 22 with glibc-2.21-13.fc22.i686
     * * Fedora 23 with glibc-2.22-18.fc23.i686
     * * Fedora 24 with glibc-2.23.1-12.fc24.i686
     * * Fedora 25 with glibc-2.24-10.fc25.i686
     * * Fedora 26 with glibc-2.25-13.fc26.i686
     * * Fedora 27 with glibc-2.26-30.fc27.i686
     * * Fedora 28 with glibc-2.27-38.fc28.i686
     * * Ubuntu 16.04 with libc6:i386 2.23-0ubuntu11
     * * Ubuntu 18.04 with libc6:i386 2.27-3ubuntu1
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc with NOP", "x86_32",
        "\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$\x90\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0cj\x01\xfft$\x08\xe8",
        "\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$\x90\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0c\xe9",
        linux_glibc_x86_32_sigjmp_buf_desc, linux_glibc_x86_32_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),
    /* This has been seen on:
     * * Arch Linux with glibc 2.30
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc", "x86_32 with endbr32 and shadow stack",
        "\xf3\x0f\x1e\xfb\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$e3\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0c\x65\xf7\x05 \0\0\0\x02\0\0\0t\x07\xf3\x0f\x1e\xc9\x89H(j\x01\xfft$\x08\xe8",
        "\xf3\x0f\x1e\xfb\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$e3\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0c\x65\xf7\x05 \0\0\0\x02\0\0\0t\x07\xf3\x0f\x1e\xc9\x89H(\xe9",
        linux_glibc_x86_32_sigjmp_buf_desc, linux_glibc_x86_32_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),
    /* This has been seen on:
     * * Fedora 29 with glibc-2.28-33.fc29.i686
     * * Fedora 30 with glibc-2.29-27.fc30.i686
     * * Fedora 31 with glibc-2.30-8.fc31.i686
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc with NOP", "x86_32 with endbr32 and shadow stack",
        "\xf3\x0f\x1e\xfb\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$\x90\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0c\x65\xf7\x05 \0\0\0\x02\0\0\0t\x07\xf3\x0f\x1e\xc9\x89H(j\x01\xfft$\x08\xe8",
        "\xf3\x0f\x1e\xfb\x8b\x44$\x04\x89\x18\x89p\x04\x89x\x08\x8dL$\x04\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x10\x8b\x0c$\x90\x65\x33\r\x18\0\0\0\xc1\xc1\t\x89H\x14\x89h\x0c\x65\xf7\x05 \0\0\0\x02\0\0\0t\x07\xf3\x0f\x1e\xc9\x89H(\xe9",
        linux_glibc_x86_32_sigjmp_buf_desc, linux_glibc_x86_32_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),

    /* https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/setjmp.S;hb=refs/tags/glibc-2.30
     * This has been seen on:
     * * Debian 8 with libc6:amd64 2.19-18+deb8u10
     * * Debian 9 with libc6:amd64 2.24-11+deb9u4
     * * Debian 10 with libc6:amd64 2.28-10
     * * Debian 11 with libc6:amd64 2.29-3
     * * Gentoo with sys-libs/glibc 2.29-r2
     * * Ubuntu 12.04 with libc6 2.15-0ubuntu10.18
     * * Ubuntu 14.04 with libc6:amd64 2.19-0ubuntu6.15
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc", "x86_64 (amd64)",
        "\xbe\x01\0\0\0",
        "H\x89\x1fH\x89\xe8\x64H3\x04%0\0\0\0H\xc1\xc0\x11H\x89G\x08L\x89g\x10L\x89o\x18L\x89w L\x89\x7f(H\x8dT$\x08\x64H3\x14%0\0\0\0H\xc1\xc2\x11H\x89W0H\x8b\x04$dH3\x04%0\0\0\0H\xc1\xc0\x11H\x89G8\xe9",
        linux_glibc_x86_64_sigjmp_buf_desc, linux_glibc_x86_64_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),
    /* There is a NOP, written in glibc as:
     * LIBC_PROBE (setjmp, 3, LP_SIZE@%RDI_LP, -4@%esi, LP_SIZE@%RAX_LP)
     * This has been seen on:
     * * Fedora 22 with glibc-2.21-13.fc22.x86_64
     * * Fedora 23 with glibc-2.22-18.fc23.x86_64
     * * Fedora 24 with glibc-2.23.1-12.fc24.x86_64
     * * Fedora 25 with glibc-2.24-10.fc25.x86_64
     * * Fedora 26 with glibc-2.25-13.fc26.x86_64
     * * Fedora 27 with glibc-2.26-30.fc27.x86_64
     * * Fedora 28 with glibc-2.27-38.fc28.x86_64
     * * Ubuntu 16.04 with libc6:amd64 2.23-0ubuntu11
     * * Ubuntu 18.04 with libc6:amd64 2.27-3ubuntu1
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc with NOP", "x86_64 (amd64)",
        "\xbe\x01\0\0\0",
        "H\x89\x1fH\x89\xe8\x64H3\x04%0\0\0\0H\xc1\xc0\x11H\x89G\x08L\x89g\x10L\x89o\x18L\x89w L\x89\x7f(H\x8dT$\x08\x64H3\x14%0\0\0\0H\xc1\xc2\x11H\x89W0H\x8b\x04$\x90\x64H3\x04%0\0\0\0H\xc1\xc0\x11H\x89G8\xe9",
        linux_glibc_x86_64_sigjmp_buf_desc, linux_glibc_x86_64_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),
    /* Use Intel CET (Control-flow Enforcement Technology), since glibc 2.28, with:
     * * indirect branch tracking (IBT), that adds "endbr64" instructions
     * * shadow stack (SHSTK), that uses "rdsspd" instruction to save the shadow stack pointer
     * This has been seen on:
     * * Arch Linux with glibc 2.30
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc", "x86_64 (amd64) with endbr64 and shadow stack",
        "\xf3\x0f\x1e\xfa\xbe\x01\0\0\0",
        "\xf3\x0f\x1e\xfaH\x89\x1fH\x89\xe8\x64H3\x04%0\0\0\0H\xc1\xc0\x11H\x89G\x08L\x89g\x10L\x89o\x18L\x89w L\x89\x7f(H\x8dT$\x08\x64H3\x14%0\0\0\0H\xc1\xc2\x11H\x89W0H\x8b\x04$dH3\x04%0\0\0\0H\xc1\xc0\x11H\x89G8d\xf7\x04%H\0\0\0\x02\0\0\0t\t\xf3H\x0f\x1e\xc8H\x89GX\xe9",
        linux_glibc_x86_64_sigjmp_buf_desc, linux_glibc_x86_64_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),
    /* This has been seen on:
     * * Fedora 29 with glibc-2.28-33.fc29.x86_64
     * * Fedora 30 with glibc-2.29-27.fc30.x86_64
     * * Fedora 31 with glibc-2.30-8.fc31.x86_64
     */
    DEFINE_KNOWN_LIBC("Linux", "glibc with NOP", "x86_64 (amd64) with endbr64 and shadow stack",
        "\xf3\x0f\x1e\xfa\xbe\x01\0\0\0",
        "\xf3\x0f\x1e\xfaH\x89\x1fH\x89\xe8\x64H3\x04%0\0\0\0H\xc1\xc0\x11H\x89G\x08L\x89g\x10L\x89o\x18L\x89w L\x89\x7f(H\x8dT$\x08\x64H3\x14%0\0\0\0H\xc1\xc2\x11H\x89W0H\x8b\x04$\x90\x64H3\x04%0\0\0\0H\xc1\xc0\x11H\x89G8d\xf7\x04%H\0\0\0\x02\0\0\0t\t\xf3H\x0f\x1e\xc8H\x89GX\xe9",
        linux_glibc_x86_64_sigjmp_buf_desc, linux_glibc_x86_64_sigjmp_buf_desc,
        glibc_unmangle_value, glibc_unmangle_value),

    /* http://git.musl-libc.org/cgit/musl/tree/src/setjmp/x86_64/setjmp.s?h=v1.1.24 */
    /* http://git.musl-libc.org/cgit/musl/tree/src/signal/x86_64/sigsetjmp.s?h=v1.1.24 */
    DEFINE_KNOWN_LIBC("Linux", "musl<1.2.2", "x86_64 (amd64)",
        "H\x89\x1fH\x89o\x08L\x89g\x10L\x89o\x18L\x89w L\x89\x7f(H\x8dT$\x08H\x89W0H\x8b\x14$H\x89W8H1\xc0\xc3",
        "",
        linux_musl_x86_64_jmp_buf_desc, linux_musl_x86_64_sigjmp_buf_desc,
        NULL, NULL),
    /* http://git.musl-libc.org/cgit/musl/tree/src/setjmp/x86_64/setjmp.s?h=v1.2.2
     * Commit http://git.musl-libc.org/cgit/musl/commit/?id=c6a6fe4ccdba92c518dfbf337cda1bf0f697527d
     * removed a useless REX-prefix on xor %eax, %eax
     */
    DEFINE_KNOWN_LIBC("Linux", "musl>=1.2.2", "x86_64 (amd64)",
        "H\x89\x1fH\x89o\x08L\x89g\x10L\x89o\x18L\x89w L\x89\x7f(H\x8dT$\x08H\x89W0H\x8b\x14$H\x89W81\xc0\xc3",
        "",
        linux_musl_x86_64_jmp_buf_desc, linux_musl_x86_64_sigjmp_buf_desc,
        NULL, NULL),

    /* https://github.com/wine-mirror/wine/blob/wine-5.22/dlls/msvcrt/except_i386.c#L1026-L1041 */
    DEFINE_KNOWN_LIBC("Windows", "Wine msvcrt.dll", "x86_32",
        "\x8bL$\x04\x89)\x89Y\x04\x89y\x08\x89q\x0c\x89\x61\x10\x8b\x04$\x89\x41\x14\xe9",
        "",
        windows_x86_32_jmp_buf_desc, no_sigjmp_buf_desc, NULL, NULL),
    /* https://github.com/wine-mirror/wine/blob/wine-1.8.7/dlls/msvcrt/except_x86_64.c#L286-L321
     * Patterns for 5-bytes jump/padding depends on the compiler:
     * Debian 8 (x86_64-w64-mingw32-gcc 4.9.1):
     * Fedora 22 (x86_64-w64-mingw32-gcc 5.1.0):
     * Fedora 23 (x86_64-w64-mingw32-gcc 5.3.0):
     *     0: e9 00 00 00 00    jmpq 0x5
     * Debian 9 (x86_64-w64-mingw32-gcc 6.3.0):
     *     0: eb 03             jmp  0x5
     *     2: 1f 00             nopl (%rax)
     */
    DEFINE_KNOWN_LIBC("Windows", "Wine 1.5...4.10 msvcrt.dll from MinGW-gcc<6", "x86_64 (amd64)",
        "H1\xd2\xe9\0\0\0\0H\x89\x11H\x89Y\x08H\x8d\x44$\x08H\x89\x41\x10H\x89i\x18H\x89q H\x89y(L\x89\x61\x30L\x89i8L\x89q@L\x89yHH\x8b\x04$H\x89\x41Pf\x0f\x7fq`f\x0f\x7fypfD\x0f\x7f\x81\x80\0\0\0\x66\x44\x0f\x7f\x89\x90\0\0\0\x66\x44\x0f\x7f\x91\xa0\0\0\0\x66\x44\x0f\x7f\x99\xb0\0\0\0\x66\x44\x0f\x7f\xa1\xc0\0\0\0\x66\x44\x0f\x7f\xa9\xd0\0\0\0\x66\x44\x0f\x7f\xb1\xe0\0\0\0\x66\x44\x0f\x7f\xb9\xf0\0\0\0H1\xc0\xc3",
        "",
        windows_x86_64_jmp_buf_desc, no_sigjmp_buf_desc, NULL, NULL),
    DEFINE_KNOWN_LIBC("Windows", "Wine 1.5...4.10 msvcrt.dll from MinGW-gcc>=6", "x86_64 (amd64)",
        "H1\xd2\xeb\x03\x0f\x1f\0H\x89\x11H\x89Y\x08H\x8d\x44$\x08H\x89\x41\x10H\x89i\x18H\x89q H\x89y(L\x89\x61\x30L\x89i8L\x89q@L\x89yHH\x8b\x04$H\x89\x41Pf\x0f\x7fq`f\x0f\x7fypfD\x0f\x7f\x81\x80\0\0\0\x66\x44\x0f\x7f\x89\x90\0\0\0\x66\x44\x0f\x7f\x91\xa0\0\0\0\x66\x44\x0f\x7f\x99\xb0\0\0\0\x66\x44\x0f\x7f\xa1\xc0\0\0\0\x66\x44\x0f\x7f\xa9\xd0\0\0\0\x66\x44\x0f\x7f\xb1\xe0\0\0\0\x66\x44\x0f\x7f\xb9\xf0\0\0\0H1\xc0\xc3",
        "",
        windows_x86_64_jmp_buf_desc, no_sigjmp_buf_desc, NULL, NULL),
    /* https://github.com/wine-mirror/wine/blob/wine-5.15/dlls/winecrt0/exception.c#L69-L94 */
    DEFINE_KNOWN_LIBC("Windows", "Wine 4.10...6.12 msvcrt.dll", "x86_64 (amd64)",
        "H\x89\x11H\x89Y\x08H\x8d\x44$\x08H\x89\x41\x10H\x89i\x18H\x89q H\x89y(L\x89\x61\x30L\x89i8L\x89q@L\x89yHH\x8b\x04$H\x89\x41Pf\x0f\x7fq`f\x0f\x7fypfD\x0f\x7f\x81\x80\0\0\0\x66\x44\x0f\x7f\x89\x90\0\0\0\x66\x44\x0f\x7f\x91\xa0\0\0\0\x66\x44\x0f\x7f\x99\xb0\0\0\0\x66\x44\x0f\x7f\xa1\xc0\0\0\0\x66\x44\x0f\x7f\xa9\xd0\0\0\0\x66\x44\x0f\x7f\xb1\xe0\0\0\0\x66\x44\x0f\x7f\xb9\xf0\0\0\0H1\xc0\xc3",
        "",
        windows_x86_64_jmp_buf_desc, no_sigjmp_buf_desc, NULL, NULL),
    /* https://github.com/wine-mirror/wine/blob/wine-6.13/dlls/winecrt0/setjmp.c#L55-L82 */
    DEFINE_KNOWN_LIBC("Windows", "Wine 6.13... msvcrt.dll", "x86_64 (amd64)",
        "H\x89\x11H\x89Y\x08H\x8d\x44$\x08H\x89\x41\x10H\x89i\x18H\x89q H\x89y(L\x89\x61\x30L\x89i8L\x89q@L\x89yHH\x8b\x04$H\x89\x41P\x0f\xaeYX\xd9y\\f\x0f\x7fq`f\x0f\x7fypfD\x0f\x7f\x81\x80\0\0\0\x66\x44\x0f\x7f\x89\x90\0\0\0\x66\x44\x0f\x7f\x91\xa0\0\0\0\x66\x44\x0f\x7f\x99\xb0\0\0\0\x66\x44\x0f\x7f\xa1\xc0\0\0\0\x66\x44\x0f\x7f\xa9\xd0\0\0\0\x66\x44\x0f\x7f\xb1\xe0\0\0\0\x66\x44\x0f\x7f\xb9\xf0\0\0\0H1\xc0\xc3",
        "",
        windows_x86_64_jmp_buf_desc, no_sigjmp_buf_desc, NULL, NULL),
    /* Windows uses stmxcsr 0x58(%rcx);fnstcw 0x5c(%rcx) to save SSE and FPU control registers */
    DEFINE_KNOWN_LIBC("Windows", "Windows msvcrt.dll (with SSE and FPU)", "x86_64 (amd64)",
        "H\x89\x11H\x89Y\x08H\x89i\x18H\x89q H\x89y(L\x89\x61\x30L\x89i8L\x89q@L\x89yHL\x8d\x44$\x08L\x89\x41\x10L\x8b\x04$L\x89\x41P\x0f\xaeYX\xd9y\\f\x0f\x7fq`f\x0f\x7fypfD\x0f\x7f\x81\x80\0\0\0\x66\x44\x0f\x7f\x89\x90\0\0\0\x66\x44\x0f\x7f\x91\xa0\0\0\0\x66\x44\x0f\x7f\x99\xb0\0\0\0\x66\x44\x0f\x7f\xa1\xc0\0\0\0\x66\x44\x0f\x7f\xa9\xd0\0\0\0\x66\x44\x0f\x7f\xb1\xe0\0\0\0\x66\x44\x0f\x7f\xb9\xf0\0\0\0\x33\xc0\xc3",
        "",
        windows_x86_64_jmp_buf_desc, no_sigjmp_buf_desc, NULL, NULL),
};

static void hexdump_as_escstring(const uint8_t *data, size_t size)
{
    size_t idx;
    char c;
    bool last_has_been_hex_escaped = false;

    for (idx = 0; idx < size; idx++) {
        if (!data[idx]) {
            printf("\\0");
            last_has_been_hex_escaped = true; /* Prevent digits from appearing after \0 */
        } else if (data[idx] == 0x09) {
            printf("\\t");
            last_has_been_hex_escaped = false;
        } else if (data[idx] == 0x0a) {
            printf("\\n");
            last_has_been_hex_escaped = false;
        } else if (data[idx] == 0x0d) {
            printf("\\r");
            last_has_been_hex_escaped = false;
        } else if (data[idx] == 0x22) {
            printf("\\\"");
            last_has_been_hex_escaped = false;
        } else if (data[idx] == 0x5c) {
            printf("\\\\");
            last_has_been_hex_escaped = false;
        } else if (data[idx] >= 0x20 && data[idx] < 0x7f) {
            /* Skip hexdigits if they follow an escape sequence */
            c = (char)data[idx];
            if (last_has_been_hex_escaped && ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                printf("\\x%02x", data[idx]);
                last_has_been_hex_escaped = true;
            } else {
                printf("%c", c);
                last_has_been_hex_escaped = false;
            }
        } else {
            printf("\\x%02x", data[idx]);
            last_has_been_hex_escaped = true;
        }
    }
}

/**
 * Identify the underlying C library using pattern matching
 */
static const struct known_libc *identify_libc(void)
{
    unsigned long idx;
    const uint8_t *setjmp_addr = (const uint8_t *)(uintptr_t)setjmp_symbol;
    uintptr_t setjmp_pcshift = 0;
#ifdef sigsetjmp_symbol
    const uint8_t *sigsetjmp_addr = (const uint8_t *)(uintptr_t)sigsetjmp_symbol;
    uintptr_t sigsetjmp_pcshift = 0;
#endif

#if defined(__arm__)
    /* Detect Thumb mode */
    setjmp_pcshift = ((uintptr_t)setjmp_addr) & 1;
    setjmp_addr -= setjmp_pcshift;
#    ifdef sigsetjmp_symbol
    sigsetjmp_pcshift = ((uintptr_t)sigsetjmp_addr) & 1;
    sigsetjmp_addr -= sigsetjmp_pcshift;
#    endif
#endif

    if (setjmp_pcshift) {
        printf("setjmp is at %#" PRIxPTR " +%#" PRIxPTR "\n", (uintptr_t)setjmp_addr, setjmp_pcshift);
    } else {
        printf("setjmp is at %#" PRIxPTR "\n", (uintptr_t)setjmp_addr);
    }

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
    /* On Windows, setjmp actually points to a trampoline such as (x86_64):
     *   0000000000407568 <_setjmp>:
     *     407568: ff 25 be 9d 00 00  jmpq *0x9dbe(%rip)  # 41132c <__imp__setjmp>
     *     40756e: 90                 nop
     *     40756f: 90                 nop
     * or (x86):
     *   004077c8 <__setjmp>:
     *     4077c8: ff 25 c0 f1 40 00  jmp *0x40f1c0
     *     4077ce: 90                 nop
     *     4077cf: 90                 nop
     * where __imp__setjmp is the address of setjmp in the import table.
     *
     * Use this address instead.
     *
     * => indirect jump to *0x41132c = 0x6a094f90
     *
     * On Linux with Wine (x86_64), this is in /usr/lib/wine/msvcrt.dll:
     *     export table for _setjmp:
     *        [ 570] +base[ 571] 14f90 Export RVA
     *     6a094f90: e9 db e6 04 00  jmpq 6a0e3670 <.text+0x62670>
     *     export table for _setjmpex:
     *        [ 571] +base[ 572] 63670 Export RVA
     *     6a0e3670: 48 89 11        mov  %rdx,(%rcx) ...
     */
    if (setjmp_addr[0] == 0xff && setjmp_addr[1] == 0x25) {
        /* Indirect jmp */
        int32_t indirect_jmp_imm32 = 0;
        const uint8_t *import_addr_entry;
        uintptr_t imported_setjmp = 0;

        memmove(&indirect_jmp_imm32, setjmp_addr + 2, 4);
#    if defined(__x86_64__)
        assert(sizeof(imported_setjmp) == 8);
        import_addr_entry = setjmp_addr + 6 + indirect_jmp_imm32;
        memmove(&imported_setjmp, import_addr_entry, 8);
#    elif defined(__i386__)
        assert(sizeof(imported_setjmp) == 4);
        import_addr_entry = (const uint8_t *)indirect_jmp_imm32;
        memmove(&imported_setjmp, import_addr_entry, 4);
#    else
#        error Unknown target architecture for Windows
#    endif
        setjmp_addr = (const uint8_t *)imported_setjmp;
        printf("=> indirect jump (imported function) to *%#" PRIxPTR " = %#" PRIxPTR "\n",
               (uintptr_t)import_addr_entry, (uintptr_t)setjmp_addr);

#    if defined(__x86_64__)
        if (setjmp_addr[0] == 0xe9) {
            /* Direct jmp +imm32 on x86_64: https://github.com/wine-mirror/wine/blob/wine-5.22/dlls/msvcrt/except_x86_64.c#L702-L703 */
            int32_t direct_jmp_imm32 = 0;

            memmove(&direct_jmp_imm32, setjmp_addr + 1, 4);
            setjmp_addr = setjmp_addr + 5 + direct_jmp_imm32;
            printf("=> direct jump to %#" PRIxPTR "\n",
                   (uintptr_t)setjmp_addr);
        } else if (setjmp_addr[0] == 0xeb) {
            /* Direct jmp +imm8 on x86_64: https://github.com/wine-mirror/wine/blob/wine-3.0.5/dlls/msvcrt/except_x86_64.c#L694-L695 */
            int8_t direct_jmp_imm8 = 0;

            memmove(&direct_jmp_imm8, setjmp_addr + 1, 1);
            setjmp_addr = setjmp_addr + 2 + direct_jmp_imm8;
            printf("=> direct jump to %#" PRIxPTR "\n",
                   (uintptr_t)setjmp_addr);
        }
#    endif
    }
#endif

#ifdef sigsetjmp_symbol
    if (sigsetjmp_pcshift) {
        printf("sigsetjmp is at %#" PRIxPTR " +%#" PRIxPTR "\n", (uintptr_t)sigsetjmp_addr, sigsetjmp_pcshift);
    } else {
        printf("sigsetjmp is at %#" PRIxPTR "\n", (uintptr_t)sigsetjmp_addr);
    }
#else
    printf("sigsetjmp is not defined on this platform.\n");
#endif

    for (idx = 0; idx < sizeof(libc_database) / sizeof(libc_database[0]); idx++) {
        if (!libc_database[idx].setjmp_code_len && !libc_database[idx].sigsetjmp_code_len)
            continue;
        if (memcmp(setjmp_addr, libc_database[idx].setjmp_code, libc_database[idx].setjmp_code_len))
            continue;
#    ifdef sigsetjmp_symbol
        if (memcmp(sigsetjmp_addr, libc_database[idx].sigsetjmp_code, libc_database[idx].sigsetjmp_code_len))
            continue;
#    endif
        return &libc_database[idx];
    }

    printf("setjmp first bytes are: ");
    hexdump_as_escstring(setjmp_addr, 200);
    printf("\n");

#ifdef sigsetjmp_symbol
    printf("sigsetjmp first bytes are: ");
    hexdump_as_escstring(sigsetjmp_addr, 200);
    printf("\n");
#endif
    return NULL;
}

#define UINTPTR_0x_PRINTLEN ((int)(sizeof(uintptr_t) * 2 + 2))

/**
 * Analyze a jmp_buf or sigjmp_buf structure with uintptr_t "registers"
 */
#define JMP_BUF_NREGS ((unsigned long)(sizeof(jmp_buf) / (sizeof(uintptr_t))))
union introspected_jmp_buf {
    jmp_buf env;
    uintptr_t env_regs[JMP_BUF_NREGS];
};
#ifdef sigsetjmp_symbol
#    define SIGJMP_BUF_NREGS ((unsigned long)(sizeof(sigjmp_buf) / (sizeof(uintptr_t))))
union introspected_sigjmp_buf {
    sigjmp_buf env;
    uintptr_t env_regs[SIGJMP_BUF_NREGS];
};
#endif

static int exit_code = 0;

static void diff_registers(const uintptr_t *data_00, const uintptr_t *data_ff, unsigned long nregs,
                           const char *const *desc, unsigned long desc_size,
                           uintptr_t (*unmangle_value)(unsigned long idx, uintptr_t value))
{
    unsigned long reg_idx, real_nregs;
    uintptr_t value, unwrapped;

    /* Skip padding */
    real_nregs = nregs;
    while (real_nregs > 0 && data_00[real_nregs - 1] == 0 && data_ff[real_nregs - 1] == (uintptr_t)-1) {
        real_nregs -= 1;
    }

    for (reg_idx = 0; reg_idx < real_nregs; reg_idx++) {
        printf("  [%2lu: @%#05lx] ", reg_idx, reg_idx * (unsigned int)sizeof(uintptr_t));

        value = data_00[reg_idx];
        /* Mark in-structure padding */
        if (reg_idx < desc_size && value == 0 && data_ff[reg_idx] == (uintptr_t)-1) {
            if (desc[reg_idx] && *desc[reg_idx]) {
                printf("(padding, may be %s)\n", desc[reg_idx]);
            } else {
                printf("(padding)\n");
            }
            continue;
        }

        printf("%#*" PRIxPTR, UINTPTR_0x_PRINTLEN, value);
        if (data_ff[reg_idx] != value) {
            printf(" (or %#*" PRIxPTR ")", UINTPTR_0x_PRINTLEN, data_ff[reg_idx]);
        }
        if (reg_idx < desc_size && desc[reg_idx] && *desc[reg_idx]) {
            printf(" = %s", desc[reg_idx]);
        } else {
            /* Return an error when an unknown field is encountered */
            printf(" = UNKNOWN!");
            exit_code = 1;
        }
        if (unmangle_value) {
            unwrapped = unmangle_value(reg_idx, value);
            if (unwrapped != value) {
                printf(" => %#*" PRIxPTR, UINTPTR_0x_PRINTLEN, unwrapped);
            }
        }
        printf("\n");
    }
}

int main(void)
{
    union introspected_jmp_buf inenv[2];
#ifdef sigsetjmp_symbol
    union introspected_sigjmp_buf insigenv[2];
#endif

    /* Use "static" in order to work around a -Wclobbered warning reported by gcc 4.9.2 (Debian 8) on x86-64 */
    static unsigned int iteration;

    g_current_libc = identify_libc();
    if (!g_current_libc) {
        fprintf(stderr, "Unable to identify the C library\n");
        return 1;
    }
    printf("Identified C library:\n");
    printf("  OS:   %s\n", g_current_libc->os_name);
    printf("  libc: %s\n", g_current_libc->libc_name);
    printf("  arch: %s\n", g_current_libc->arch_name);

    memset(&inenv[0], 0, sizeof(union introspected_jmp_buf));
    memset(&inenv[1], 0xff, sizeof(union introspected_jmp_buf));
#ifdef sigsetjmp_symbol
    memset(&insigenv[0], 0, sizeof(union introspected_sigjmp_buf));
    memset(&insigenv[1], 0xff, sizeof(union introspected_sigjmp_buf));
#endif

    printf("Some addresses:\n");
    printf("  main  = %#*" PRIxPTR "\n", UINTPTR_0x_PRINTLEN, (uintptr_t)main);
    printf("  frame = %#*" PRIxPTR "\n", UINTPTR_0x_PRINTLEN, (uintptr_t)(void *)__builtin_frame_address(0));
    printf("\n");

    printf("sizeof(jmp_buf) = %#lx = %lu (%lu registers):\n",
           (unsigned long)sizeof(jmp_buf), (unsigned long)sizeof(jmp_buf), JMP_BUF_NREGS);
    assert(sizeof(inenv[0].env_regs) == sizeof(jmp_buf));
    assert((void *)&inenv[0].env_regs == (void *)&inenv[0].env);
    assert((void *)&inenv[1].env_regs == (void *)&inenv[1].env);
    /* Perform 2 iterations, once with a buffer filled with 0 and once with one filled with FF */
    for (iteration = 0; iteration < 2; iteration++) {
        setjmp(inenv[iteration].env);
    }
    diff_registers(inenv[0].env_regs, inenv[1].env_regs, JMP_BUF_NREGS,
                   g_current_libc->jmp_buf_desc, g_current_libc->jmp_buf_count,
                   g_current_libc->unmangle_jmp_buf_value);

#ifdef sigsetjmp_symbol
    printf("\n");

    printf("sizeof(sigjmp_buf) = %#lx = %lu (%lu registers):\n",
           (unsigned long)sizeof(sigjmp_buf), (unsigned long)sizeof(sigjmp_buf), SIGJMP_BUF_NREGS);
    assert(sizeof(insigenv[0].env_regs) == sizeof(sigjmp_buf));
    assert((void *)&insigenv[0].env_regs == (void *)&insigenv[0].env);
    assert((void *)&insigenv[1].env_regs == (void *)&insigenv[1].env);
    for (iteration = 0; iteration < 2; iteration++) {
        /* Ask for saving the process's current signal mask */
        sigsetjmp(insigenv[iteration].env, 1);
    }
    diff_registers(insigenv[0].env_regs, insigenv[1].env_regs, JMP_BUF_NREGS,
                   g_current_libc->sigjmp_buf_desc, g_current_libc->sigjmp_buf_count,
                   g_current_libc->unmangle_sigjmp_buf_value);
#endif
    return exit_code;
}
