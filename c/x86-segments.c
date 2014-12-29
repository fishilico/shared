/**
 * Show x86 segment information
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#    ifdef __x86_64__
#        include <asm/prctl.h>
#        include <asm/unistd.h>
#        include <unistd.h>
/* x86_64 Linux segment indexes in the Global Descriptor Table (GDT)
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/segment.h
 */
static const char *const gdt_segment_index_desc[16] = {
    NULL,
    "krnl CS32", /* GDT_ENTRY_KERNEL32_CS = 1 */
    "krnl CS", /* GDT_ENTRY_KERNEL_CS = 2 */
    "krnl DS", /* GDT_ENTRY_KERNEL_DS = 3 */
    "user CS32", /* GDT_ENTRY_DEFAULT_USER32_CS = 4 */
    "user DS", /* GDT_ENTRY_DEFAULT_USER_DS = 5 */
    "user CS", /* GDT_ENTRY_DEFAULT_USER_CS = 6 */
    NULL,
    "TSS1", "TSS2", /* GDT_ENTRY_TSS = 8 */
    "LDT1", "LDT2", /* GDT_ENTRY_LDT = 10 */
    "TLS1", "TLS2", "TLS3", /* GDT_ENTRY_TLS_MIN = 12,  GDT_ENTRY_TLS_MAX = 14 */
    "percpu", /* GDT_ENTRY_PER_CPU = 15 */
};
#    elif defined(__i386__)
#       include <asm/ldt.h>
#       include <linux/unistd.h>
#       include <unistd.h>
/* A 32-bit compiled program sees 64-bit segment indexes when run on a 64-bit kernel.
 * Therefore show information for both 32- and 64-bit x86 architectures here
 */
static const char *const gdt_segment_index_desc[32] = {
    NULL, NULL, NULL, NULL, "x64 user CS32", "x64 user DS",
    "x86 TLS1 or x64 user CS", "TLS2", "TLS3", /* GDT_ENTRY_TLS_MIN = 6,  GDT_ENTRY_TLS_MAX = 8 */
    NULL, NULL, NULL,
    "x86 krnl CS or x64 TLS1", /* GDT_ENTRY_KERNEL_CS = 12 */
    "x86 krnl DS", /* GDT_ENTRY_KERNEL_DS = 13 */
    "x86 user CS", /* GDT_ENTRY_DEFAULT_USER_CS = 14 */
    "x86 user DS or x64 percpu", /* GDT_ENTRY_DEFAULT_USER_DS = 15 */
    "x86 TSS", /* GDT_ENTRY_TSS = 16 */
    "x86 LDT", /* GDT_ENTRY_LDT = 17 */
    NULL, NULL, NULL, NULL, NULL, /* GDT_ENTRY_PNPBIOS_BASE = 18 */
    NULL, NULL, NULL, /* APMBIOS_BASE = 23 */
    "espfix", /* GDT_ENTRY_ESPFIX_SS = 26 */
    "percpu", /* GDT_ENTRY_ESPFIX_SS = 27 */
};
#    endif
#else
static const char *const gdt_segment_index_desc[1] = { NULL };
#endif

#if defined(__i386__) || defined(__x86_64__)

/**
 * Display a textual description of the specified segment selector:
 * * bits 0-1: Requested Privilege Level (RPL)
 * * bit 2: Task Indicator (TI), 0=GDT, 1=LDT
 * * bits 3-15: index
 */
static void print_segment_desc(const char *segname, uint16_t segment)
{
    uint8_t lsl_ok = 0;
    uint32_t limit;

    /* Use a segment limit, loaded with "lsl" */
    __asm__ volatile ("lsll %2, %0 ; setz %1"
        : "=r" (limit), "=q" (lsl_ok)
        : "r" ((uint32_t)segment)
        : "cc");
    if (segname) {
        printf("%s=0x%04x", segname, segment);
        if (segment) {
            printf(" (index=%d, RPL=%d", segment >> 3, segment & 3);
            if (segment & 4) {
                printf(", TI=1:LDT");
            }
            printf(")");
        }
        if (lsl_ok) {
            printf(", limit=0x%x", limit);
        }
        printf("\n");
    } else if (lsl_ok) {
        unsigned int index = segment >> 3;
        printf("%4u: selector 0x%04x", index, segment);
        printf(", limit=0x%x", limit);
        if (index < sizeof(gdt_segment_index_desc) / sizeof(gdt_segment_index_desc[0])) {
            printf(", %s", gdt_segment_index_desc[index]);
        }
        printf("\n");
    }
}

static void print_segments(void)
{
    printf("Segments:\n");
#define analyze_segment(segname) \
    do { \
        uint16_t segment; \
        __asm__ volatile ("movw %%" #segname ", %0" : "=g" (segment)); \
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
    printf("  fs base=0x%lx\n", base);
    syscall(__NR_arch_prctl, ARCH_GET_GS, &base);
    printf("  gs base=0x%lx\n", base);
#elif defined(__i386__) && defined(__linux__)
    uint16_t segment;
    unsigned long limit;
    struct user_desc u_info;

    printf("Segment bases:\n");
    __asm__ volatile ("movw %%fs, %0" : "=g" (segment));
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
            printf("  fs base=0x%lx, limit=0x%lx\n", (unsigned long)u_info.base_addr, limit);
        }
    }
    __asm__ volatile ("movw %%gs, %0" : "=g" (segment));
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
            printf("  gs base=0x%lx, limit=0x%lx\n", (unsigned long)u_info.base_addr, limit);
        }
    }
#else
    printf("No known way to get segment bases.\n");
#endif
}

static void print_gdt_limits(void)
{
    uint8_t gdt_descriptor[2 + sizeof(uintptr_t)];
    uint16_t gdt_size, segment;

    /* Read GDT size to get the number of entries */
    __asm__ volatile ("sgdt %0" : "=m" (gdt_descriptor));
    memcpy(&gdt_size, gdt_descriptor, 2);

    printf("GDT limits (%u entries):\n", (gdt_size + 1) / 8);
    for (segment = 3; segment < gdt_size; segment += 8) {
        print_segment_desc(NULL, segment);
    }
}

int main(void)
{
    print_segments();
    printf("\n");
    print_segment_bases();
    printf("\n");
    print_gdt_limits();
    return 0;
}

#else
int main(void)
{
    fprintf(stderr, "The architecture is not x86.\n");
    return 1;
}
#endif
