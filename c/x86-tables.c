/**
 * Show current addresses of GDT and IDT
 *
 * Linux-specific information
 * --------------------------
 * On Linux it might be useful to check whether kASLR is enabled by doing:
 *    grep _stext /proc/kallsyms /boot/System.map-$(uname -r)
 * ... if the two given addresses are equal, kASLR is disabled.
 * Nevertheless kernel addresses read from unprivileged instructions like sidt
 * do not depend on the kernel random base address ;)
 *
 * The GDT address is per_cpu(gdt_page, cpu)
 * Documentation:
 * * arch/x86/kernel/cpu/common.c: switch_to_new_gdt
 * * arch/x86/include/asm/desc_defs.h: get_cpu_gdt_table, load_gdt
 *
 * The IDT is fix_to_virt(FIX_RO_IDT) for userspace, which is mapped to kernel
 * data idt_table in trap_init:
 *     __set_fixmap(FIX_RO_IDT, __pa_symbol(idt_table), PAGE_KERNEL_RO);
 *     idt_descr.address = fix_to_virt(FIX_RO_IDT);
 * Documentation:
 * * arch/x86/kernel/cpu/common.c: cpu_init
 * * arch/x86/include/asm/desc_defs.h: load_current_idt, load_idt
 * * arch/x86/kernel/traps.c: trap_init
 */
#if !defined(_GNU_SOURCE) && defined(__linux__)
#    define _GNU_SOURCE /* for sched_getaffinity, sched_setaffinity... */
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x86-umip-recovery.h"

/**
 * Setting CPU affinity is an OS-dependent operation, hence the #if parts
 */
#ifdef __linux__
#    include <errno.h>
#    include <sched.h>

static const char os_name[] = "Linux";
static const char gdt_comment[] = "per_cpu(gdt_page, cpu) or fix_to_virt(FIX_GDT_REMAP_BEGIN + cpu) since 4.12";
static const char idt_comment[] = "fix_to_virt(FIX_RO_IDT)";

static cpu_set_t initial_cpuset;

static void initialize_cpu_affinity(void)
{
    CPU_ZERO(&initial_cpuset);
    if (sched_getaffinity(0, sizeof(initial_cpuset), &initial_cpuset) == -1) {
        perror("sched_getaffinity");
        exit(1);
    }
}

static int get_next_cpu(int cpu)
{
    if (cpu < 0) {
        return -1;
    }
    do {
        cpu++;
        if (cpu >= (int)(sizeof(initial_cpuset.__bits) / sizeof(initial_cpuset.__bits[0]))) {
            return -1;
        }
    } while (!CPU_ISSET(cpu, &initial_cpuset));
    return cpu;
}

/**
 * Set CPU affinity to migrate to cpu
 */
static void migrate_to_cpu(int cpu)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == -1) {
        if (errno == EINVAL && cpu == 0) {
            printf("Warning: unable to migrate to CPU 0 (maybe offline). Showing current CPU...\n");
            return;
        }
        perror("sched_setaffinity");
        exit(1);
    }
}
#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
#    include <windows.h>

/* The addresses of GDT and IDT changed a lot across Windows versions:
 * https://code.google.com/p/corkami/wiki/InitialValues?wl=en
 */
static const char os_name[] = "Windows";
static const char gdt_comment[] = "?";
static const char idt_comment[] = "?";

static DWORD_PTR InitialAffinityMask;

static void initialize_cpu_affinity(void)
{
    DWORD_PTR ProcessAffinityMask, SystemAffinityMask;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessAffinityMask, &SystemAffinityMask)) {
        fprintf(stderr, "GetProcessAffinityMask: error %lu\n", GetLastError());
        exit(1);
    }
    if (ProcessAffinityMask != SystemAffinityMask) {
        fprintf(stderr, "Warning: process affinity mask 0x%lx != system 0x%lx\n",
                (ULONG)ProcessAffinityMask, (ULONG)SystemAffinityMask);
        ProcessAffinityMask &= SystemAffinityMask;
    } else if (!ProcessAffinityMask) {
        /* Wine may return 0 when strange things are in place */
        fprintf(stderr, "Warning: process affinity mask is 0, not changing CPU.\n");
    }
    InitialAffinityMask = ProcessAffinityMask;
}

static int get_next_cpu(int cpu)
{
    if (cpu < 0) {
        return -1;
    }
    do {
        cpu++;
        if (cpu >= (int)(8 * sizeof(DWORD_PTR))) {
            return -1;
        }
    } while (!(InitialAffinityMask & (((DWORD_PTR)1) << cpu)));
    return cpu;
}

/**
 * Set CPU affinity to migrate to cpu
 */
static void migrate_to_cpu(int cpu)
{
    /* Do not migrate anywhere if GetProcessAffinityMask returned 0 */
    if (!InitialAffinityMask) {
        return;
    }
    if (!SetProcessAffinityMask(GetCurrentProcess(), 1 << (unsigned)cpu)) {
        fprintf(stderr, "SetProcessAffinityMask: error %lu\n", GetLastError());
        exit(1);
    }
}
#else
#    warning Unknown target OS

/* Define wome placeholders */
static const char os_name[] = "Unknown";
static const char gdt_comment[] = "?";
static const char idt_comment[] = "?";

static void initialize_cpu_affinity(void)
{
    printf("Warning: unknown target OS, assuming single CPU!\n");
}
static int get_next_cpu(int cpu) {
    return -1;
}
static void migrate_to_cpu(int cpu) {
}
#endif

static void show_gdt(int cpu)
{
    /* Linux kernel defines a structure for a table descriptor:
     * * arch/x86/include/asm/desc_defs.h:
     *       struct desc_ptr {
     *           unsigned short size;
     *           unsigned long address;
     *       } __attribute__((packed));
     */
    uint8_t descriptor[2 + sizeof(uintptr_t)];
    uint16_t size;
    void *address;

    assert(sizeof(size) == 2);
    assert(sizeof(descriptor) == sizeof(size) + sizeof(address));

    migrate_to_cpu(cpu);

    UMIP_SECTION_START("SGDT")
    __asm__ volatile ("sgdt %0" : "=m"(descriptor) : : "memory");
    memcpy(&size, descriptor, 2);
    memcpy(&address, descriptor + 2, sizeof(void *));
    printf("CPU %2d GDT @%p, size %u (%u 8-byte entries)\n", cpu, address, size, ((unsigned int)size + 1) / 8);
    UMIP_SECTION_END
}

static void show_idt(int cpu)
{
    uint8_t descriptor[2 + sizeof(uintptr_t)];
    uint16_t size;
    void *address;

    assert(sizeof(size) == 2);
    assert(sizeof(descriptor) == sizeof(size) + sizeof(address));

    migrate_to_cpu(cpu);
    UMIP_SECTION_START("SIDT")
    __asm__ volatile ("sidt %0" : "=m"(descriptor) : : "memory");
    memcpy(&size, descriptor, 2);
    memcpy(&address, descriptor + 2, sizeof(void *));
    printf("CPU %2d IDT @%p, size %u (256 %u-byte vectors)\n", cpu, address, size, ((unsigned int)size + 1) / 256);
    UMIP_SECTION_END
}

int main(void)
{
    int cpu;

    configure_umip_recovery();
    initialize_cpu_affinity();

    /* Get GDT */
    printf("GDT (%s: %s):\n", os_name, gdt_comment);
    for (cpu = 0; cpu >= 0; cpu = get_next_cpu(cpu)) {
        /* Work around -Wclobbered false positive with old gcc by moving the
         * UMIP section into a dedicated function.
         */
        show_gdt(cpu);
    }
    printf("\n");

    /* Get IDT */
    printf("IDT (%s: %s):\n", os_name, idt_comment);
    for (cpu = 0; cpu >= 0; cpu = get_next_cpu(cpu)) {
        show_idt(cpu);
    }
    return 0;
}
