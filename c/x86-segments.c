/**
 * Show x86 segment information
 */
#if !defined(_GNU_SOURCE) && defined(__linux__)
#    define _GNU_SOURCE /* for syscall */
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#    include <sys/syscall.h>
#    include <unistd.h>
#    ifdef __x86_64__
/* x86_64 Linux segment indexes in the Global Descriptor Table (GDT)
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/segment.h
 */
static const char *const gdt_segment_index_desc[16] = {
    NULL,
    "krnl CS32", /* GDT_ENTRY_KERNEL32_CS = 1 (0x08) */
    "krnl CS", /* GDT_ENTRY_KERNEL_CS = 2 (0x10) */
    "krnl DS", /* GDT_ENTRY_KERNEL_DS = 3 (0x18) */
    "user CS32", /* GDT_ENTRY_DEFAULT_USER32_CS = 4 (0x23) */
    "user DS", /* GDT_ENTRY_DEFAULT_USER_DS = 5 (0x2b) */
    "user CS", /* GDT_ENTRY_DEFAULT_USER_CS = 6 (0x33) */
    NULL,
    "TSS1", "TSS2", /* GDT_ENTRY_TSS = 8 (0x40) */
    "LDT1", "LDT2", /* GDT_ENTRY_LDT = 10 (0x50) */
    "TLS1", "TLS2", "TLS3", /* GDT_ENTRY_TLS_MIN = 12 (0x63), GDT_ENTRY_TLS_MAX = 14 (0x73) */
    "percpu", /* GDT_ENTRY_PER_CPU = 15 (0x7b) */
};

/* glibc defines these constants in asm/prctl.h but not musl, which hardcodes
 * such constants, for example in __set_thread_area function:
 * http://git.musl-libc.org/cgit/musl/tree/src/thread/x86_64/__set_thread_area.s?id=v1.1.6
 */
#        ifndef ARCH_GET_FS
#            define ARCH_GET_FS 0x1003
#        endif
#        ifndef ARCH_GET_GS
#            define ARCH_GET_GS 0x1004
#        endif

#    elif defined(__i386__)
/* A 32-bit compiled program sees 64-bit segment indexes when run on a 64-bit kernel.
 * Therefore show information for both 32- and 64-bit x86 architectures here
 */
static const char *const gdt_segment_index_desc[32] = {
    NULL, NULL, NULL, NULL, "x64 user CS32", "x64 user DS",
    "x86 TLS1 or x64 user CS", "TLS2", "TLS3", /* GDT_ENTRY_TLS_MIN = 6 (0x33), GDT_ENTRY_TLS_MAX = 8 (0x43) */
    NULL, NULL, NULL,
    "x86 krnl CS or x64 TLS1", /* GDT_ENTRY_KERNEL_CS = 12 (0x60) */
    "x86 krnl DS", /* GDT_ENTRY_KERNEL_DS = 13 (0x68) */
    "x86 user CS", /* GDT_ENTRY_DEFAULT_USER_CS = 14 (0x73) */
    "x86 user DS or x64 percpu", /* GDT_ENTRY_DEFAULT_USER_DS = 15 (0x7b) */
    "x86 TSS", /* GDT_ENTRY_TSS = 16 (0x80) */
    "x86 LDT", /* GDT_ENTRY_LDT = 17 (0x88) */
    NULL, NULL, NULL, NULL, NULL, /* GDT_ENTRY_PNPBIOS_BASE = 18 */
    NULL, NULL, NULL, /* APMBIOS_BASE = 23 */
    "espfix", /* GDT_ENTRY_ESPFIX_SS = 26 (0xd0) */
    "percpu", /* GDT_ENTRY_PERCPU = 27 (0xdb) */
    "stack canary", /* GDT_ENTRY_STACK_CANARY = 28 (0xe0) */
    NULL, NULL,
    "doublefault TSS", /* GDT_ENTRY_DOUBLEFAULT_TSS = 31 (0xf8) */
};
#    endif
#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
#    include <inttypes.h>
#    define IS_WINDOWS
/* Some information about Windows segments can be found:
 * * by reading the Global Descriptor Table in WinDbg using Local Kernel Debugging mode
 * * in ReactOS source code:
 *   * https://git.reactos.org/?p=reactos.git;a=blob;f=reactos/include/ndk/amd64/ketypes.h
 *   * https://git.reactos.org/?p=reactos.git;a=blob;f=reactos/include/ndk/i386/ketypes.h
 * * in corkami project: https://code.google.com/p/corkami/wiki/InitialValues?wl=en
 */
#    ifdef __x86_64__
static const char *const gdt_segment_index_desc[14] = {
    NULL, NULL,
    "krnl CS", /* 0x10 */
    "krnl DS", /* 0x18 */
    "user CS32", /* 0x23 */
    "user DS", /* 0x2b */
    "user CS", /* 0x33 */
    NULL,
    "TSS", /* 0x40 */
    "TSS+1",
    "user TEB32", /* 0x53, loaded in fs, Thread Environment Block in 32-bit mode */
    NULL, NULL, NULL,
};
#    else
static const char *const gdt_segment_index_desc[11] = {
    NULL,
    "x86 krnl CS", /* 0x08 */
    "x86 krnl DS or x64 krnl CS", /* 0x10 */
    "x86 user CS or x64 krnl DS", /* 0x1b or 0x18 */
    "x86 user DS or x64 user CS32", /* 0x23 */
    "x86 TSS or x64 user DS", /* 0x28 or 0x2b */
    "x86 krnl PCR or x64 user CS", /* 0x30 or 0x33 */
    "x86 user TEB", /* 0x3b, loaded in fs */
    NULL, NULL,
    "x64 user TEB32", /* 0x53, loaded in fs */
};
#    endif
#else
#    warning Unsupported target OS
static const char *const gdt_segment_index_desc[1] = { NULL };
#endif

/**
 * Display a textual description of the specified segment selector:
 * * bits 0-1: Requested Privilege Level (RPL)
 * * bit 2: Task Indicator (TI), 0=GDT, 1=LDT
 * * bits 3-15: index
 */
static void print_segment_desc(const char *segname, uint16_t segment)
{
    uint8_t lsl_ok = 0, lar_ok = 0;
    uint32_t limit, access_rights;
    unsigned int sindex = segment >> 3;

    /* Use a segment limit, loaded with "lsl" */
    __asm__ ("lsll %2, %0 ; setz %1"
        : "=r" (limit), "=q" (lsl_ok)
        : "r" ((uint32_t)segment)
        : "cc");

    /* Load access right associated with the segment */
    __asm__ ("larl %2, %0 ; setz %1"
        : "=r" (access_rights), "=q" (lar_ok)
        : "r" ((uint32_t)segment)
        : "cc");

    if (segname) {
        printf("%s=0x%04x", segname, segment);
        if (segment) {
            printf(" (index=%u, RPL=%d", sindex, segment & 3);
            if (segment & 4) {
                printf(", TI=1:LDT");
            }
            printf(")");
        }
    } else if (lsl_ok || lar_ok) {
        printf("%4u: selector 0x%04x", sindex, segment);
    } else {
        return;
    }
    if (lsl_ok) {
        if (limit == 0xffffffff) {
            printf(", limit=-1");
        } else {
            printf(", limit=%#x", limit);
        }
    }
    if (lar_ok) {
        printf(", access=%#x", access_rights);
    }
    if (sindex && sindex < sizeof(gdt_segment_index_desc) / sizeof(gdt_segment_index_desc[0])) {
        printf(", %s", gdt_segment_index_desc[sindex]);
    }
    printf("\n");

    if (!segname && lar_ok) {
        /* Documentation: http://wiki.osdev.org/Global_Descriptor_Table */
        printf(
            "     ... %s%s%s%s%s dpl=%u%s%s%s%s\n",
            (access_rights & 0x0800) ? "Code" : "Data", /* bit 11: executable */
            (access_rights & 0x0200) ? /* bit 9: RW, readable/writable */
                ((access_rights & 0x0800) ? " RX" : " RW") :
                ((access_rights & 0x0800) ? " X" : " RO"),
            (access_rights & 0x0400) ? " Grows-Down" : "", /* bit 10: direction/conforming */
            (access_rights & 0x0100) ? "" : " not-accessed", /* bit 8: accessed */
            (access_rights & 0x1000) ? "" : " TSS", /* bit 12: s */
            (access_rights & 0x6000) >> 13, /* bits 13-14: dpl */
            (access_rights & 0x8000) ? "" : " not-present", /* bit 15: p, present */
            (access_rights & 0x100000) ? " AVL" : "", /* bit 20: avl */
            (access_rights & 0x200000) ? /* bit 21: l, long mode. bit 22: d, operand size */
                ((access_rights & 0x400000) ? " l=d=1???" : " 64-bit") :
                ((access_rights & 0x400000) ? " 32-bit" : " 16-bit"),
            (access_rights & 0x800000) ? " 4k-page" : ""); /* bit 23: g, granularity */
    }
}

static void print_segments(void)
{
    printf("Segments:\n");
#define analyze_segment(segname) \
    do { \
        uint16_t segment; \
        __asm__ ("movw %%" #segname ", %0" : "=g" (segment)); \
        print_segment_desc("  " #segname, segment); \
    } while (0)
    analyze_segment(cs);
    analyze_segment(ds);
    analyze_segment(es);
    analyze_segment(fs);
    analyze_segment(gs);
    analyze_segment(ss);
#undef analyze_segment
}

static void print_segment_bases(void)
{
#if defined(__x86_64__) && defined(__linux__)
    unsigned long base = 0;

    printf("Segment bases (0 for cs, ds, es and ss):\n");
    syscall(__NR_arch_prctl, ARCH_GET_FS, &base);
    printf("  fs base=%#lx\n", base);
    syscall(__NR_arch_prctl, ARCH_GET_GS, &base);
    printf("  gs base=%#lx\n", base);
#elif defined(__i386__) && defined(__linux__)
    uint16_t segment;
    unsigned long limit;
    /* Explicitly define user_desc as in asm/ldt.h because some libc like musl
     * doesn't provide a definition
     */
    struct user_desc {
        unsigned int entry_number;
        unsigned int base_addr;
        unsigned int limit;
        unsigned int seg_32bit:1;
        unsigned int contents:2;
        unsigned int read_exec_only:1;
        unsigned int limit_in_pages:1;
        unsigned int seg_not_present:1;
        unsigned int useable:1;
        unsigned int lm:1;
    } u_info;

    printf("Segment bases:\n");
    __asm__ ("movw %%fs, %0" : "=g" (segment));
    if (segment) {
        memset(&u_info, 0, sizeof(u_info));
        u_info.entry_number = segment >> 3;
        if (syscall(__NR_get_thread_area, &u_info) == -1) {
            perror("get_thread_area(fs)");
        } else {
            limit = u_info.limit;
            if (u_info.limit_in_pages) {
                limit = (limit << 12) | 0xfff;
            }
            printf("  fs base=%#lx, limit=%#lx\n", (unsigned long)u_info.base_addr, limit);
        }
    }
    __asm__ ("movw %%gs, %0" : "=g" (segment));
    if (segment) {
        memset(&u_info, 0, sizeof(u_info));
        u_info.entry_number = segment >> 3;
        if (syscall(__NR_get_thread_area, &u_info) == -1) {
            perror("get_thread_area(gs)");
        } else {
            limit = u_info.limit;
            if (u_info.limit_in_pages) {
                limit = (limit << 12) | 0xfff;
            }
            printf("  gs base=%#lx, limit=%#lx\n", (unsigned long)u_info.base_addr, limit);
        }
    }
#elif defined(__x86_64__) && defined(IS_WINDOWS)
    uint64_t gs_base;

    printf("Segment bases (0 for cs, ds, es and ss):\n");
    printf("  fs base= ?\n");
    __asm__ ("movq %%gs:48, %0" : "=r" (gs_base));
    printf("  gs base=%#" PRIx64 " (TEB)\n", gs_base);
#elif defined(__i386__) && defined(IS_WINDOWS)
    uint32_t fs_base;

    printf("Segment bases:\n");
    __asm__ ("movl %%fs:24, %0" : "=r" (fs_base));
    printf("  fs base=%#" PRIx32 " (TEB)\n", fs_base);
    printf("  gs base= ?\n");
#else
    printf("No known way to get segment bases.\n");
#endif
}

static void print_gdt_limits(void)
{
    uint8_t gdt_descriptor[2 + sizeof(uintptr_t)];
    uint16_t gdt_size, segment;

    /* Read GDT size to get the number of entries */
    __asm__ ("sgdt %0" : "=m" (gdt_descriptor));
    memcpy(&gdt_size, gdt_descriptor, 2);

    printf("GDT limits and access rights (%u entries):\n", (gdt_size + 1) / 8);
    for (segment = 3; segment < gdt_size; segment += 8) {
        print_segment_desc(NULL, segment);
    }
}

/**
 * Show cr0 (Control Register 0), also named "Machine Status Word"
 */
static void print_cr0(void)
{
    uint32_t cr0;

#define print_cr0_bit(bitnum, desc) \
    printf("  %2d (0x%08x) = %c %s\n", bitnum, 1U << (bitnum), \
    (cr0 & (1U << (bitnum))) ? '+' : '-', desc);

    /* smsw = Save Machine Status Word */
    __asm__ ("smsw %0" : "=r" (cr0));
    printf("cr0 = 0x%08x\n", cr0);
    print_cr0_bit(0, "PE (Protection Enable)");
    print_cr0_bit(1, "MP (Monitor Coprocessor)");
    print_cr0_bit(2, "EM (Emulation)");
    print_cr0_bit(3, "TS (Task Switched)");
    print_cr0_bit(4, "ET (Extension Type)");
    print_cr0_bit(5, "NE (Numeric Error)");
    print_cr0_bit(16, "WP (Write Protect)");
    print_cr0_bit(18, "AM (Alignment Mask)");
    print_cr0_bit(29, "NW (Not Write-through)");
    print_cr0_bit(30, "CD (Cache Disable)");
    print_cr0_bit(31, "PG (Paging)");
#undef print_cr0_bit
}

int main(void)
{
    print_segments();
    printf("\n");
    print_segment_bases();
    printf("\n");
    print_gdt_limits();
    printf("\n");
    print_cr0();
    return 0;
}
