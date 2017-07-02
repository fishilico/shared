/**
 * Use KVM to run some code
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for MAP_ANONYMOUS */
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>

/* musl uses POSIX specification for ioctl(int, int, ...) instead of glibc
 * ioctl(int, unsigned long, ...). This causes a -Woverflow to occur when
 * using read ioctl (because they have their most significant bit set).
 * Work around this by always casting the request to int when not using
 * glibc.
 */
#ifdef __GLIBC__
#    define ioctl_read(fd, req, ptr) ioctl((fd), (req), (ptr))
#else
#    define ioctl_read(fd, req, ptr) ioctl((fd), (int)(req), (ptr))
#endif

/**
 * Dump the registers of a virtual CPU
 */
static bool dump_registers(int cpufd)
{
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    size_t i;

    if (ioctl_read(cpufd, KVM_GET_REGS, &regs) < 0) {
        perror("ioctl(KVM_GET_REGS)");
        return false;
    }
    if (ioctl_read(cpufd, KVM_GET_SREGS, &sregs) < 0) {
        perror("ioctl(KVM_GET_SREGS)");
        return false;
    }
#define show_reg64(name) printf("  - %s: %#llx\n", #name, regs.name)
#define show_sreg64(name) printf("  - %s: %#llx\n", #name, sregs.name)

#if defined(__x86_64__) || defined(__i386__)
#    define show_sreg_seg(name) do { \
        printf("  - %s: segment\n", #name); \
        printf("    - base: %#llx\n", sregs.name.base); \
        printf("    - limit: %#" PRIx32 "\n", sregs.name.limit); \
        printf("    - selector: %#" PRIx16 "\n", sregs.name.selector); \
        printf("    - type: %#" PRIx8 "\n", sregs.name.type); \
        printf("    - present: %#" PRIx8 "\n", sregs.name.present); \
        printf("    - dpl: %#" PRIx8 "\n", sregs.name.dpl); \
        printf("    - db: %#" PRIx8 "\n", sregs.name.db); \
        printf("    - s: %#" PRIx8 "\n", sregs.name.s); \
        printf("    - l: %#" PRIx8 "\n", sregs.name.l); \
        printf("    - g: %#" PRIx8 "\n", sregs.name.g); \
        printf("    - avl: %#" PRIx8 "\n", sregs.name.avl); \
        printf("    - unusable: %#" PRIx8 "\n", sregs.name.unusable); \
        assert(sregs.name.padding == 0); \
        assert(sizeof(sregs.name) == 24); \
    } while (0)
#    define show_sreg_dtable(name) do { \
        printf("  - %s: descriptor table\n", #name); \
        printf("    - base: %#llx\n", sregs.name.base); \
        printf("    - limit: %#" PRIx16 "\n", sregs.name.limit); \
        assert(sregs.name.padding[0] == 0); \
        assert(sregs.name.padding[1] == 0); \
        assert(sregs.name.padding[2] == 0); \
        assert(sizeof(sregs.name) == 16); \
    } while (0)
    show_reg64(rax);
    show_reg64(rbx);
    show_reg64(rcx);
    show_reg64(rdx);
    show_reg64(rsi);
    show_reg64(rdi);
    show_reg64(rsp);
    show_reg64(rbp);
    show_reg64(r8);
    show_reg64(r9);
    show_reg64(r10);
    show_reg64(r11);
    show_reg64(r12);
    show_reg64(r13);
    show_reg64(r14);
    show_reg64(r15);
    show_reg64(rip);
    show_reg64(rflags);
    assert(sizeof(regs) == 18 * 8);

    printf("\n");
    show_sreg_seg(cs);
    show_sreg_seg(ds);
    show_sreg_seg(es);
    show_sreg_seg(fs);
    show_sreg_seg(gs);
    show_sreg_seg(ss);
    show_sreg_seg(tr);
    show_sreg_seg(ldt);
    show_sreg_dtable(gdt);
    show_sreg_dtable(idt);
    show_sreg64(cr0);
    show_sreg64(cr2);
    show_sreg64(cr3);
    show_sreg64(cr4);
    show_sreg64(cr8);
    show_sreg64(efer);
    show_sreg64(apic_base);
    printf("  - interrupt_bitmap:");
    for (i = 0; i < sizeof(sregs.interrupt_bitmap); i++) {
        printf(" %02x", ((uint8_t *)sregs.interrupt_bitmap)[i]);
    }
    printf("\n");
    assert(sizeof(sregs) == 8 * 24 + 2 * 16 + 7 * 8 + sizeof(sregs.interrupt_bitmap));
#    undef show_sreg_dtable
#    undef show_sreg_seg
#else
#    error Unsupported architecture
#endif
#undef show_reg64
#undef show_sreg64
    return true;
}

/**
 * Get the name of the VCPU exit reason
 */
static const char *get_exit_reason_name(uint32_t exit_reason)
{
    if (exit_reason == KVM_EXIT_UNKNOWN)
        return "KVM_EXIT_UNKNOWN";
    if (exit_reason == KVM_EXIT_EXCEPTION)
        return "KVM_EXIT_EXCEPTION";
    if (exit_reason == KVM_EXIT_IO)
        return "KVM_EXIT_IO";
    if (exit_reason == KVM_EXIT_HYPERCALL)
        return "KVM_EXIT_HYPERCALL";
    if (exit_reason == KVM_EXIT_DEBUG)
        return "KVM_EXIT_DEBUG";
    if (exit_reason == KVM_EXIT_HLT)
        return "KVM_EXIT_HLT";
    if (exit_reason == KVM_EXIT_MMIO)
        return "KVM_EXIT_MMIO";
    if (exit_reason == KVM_EXIT_IRQ_WINDOW_OPEN)
        return "KVM_EXIT_IRQ_WINDOW_OPEN";
    if (exit_reason == KVM_EXIT_SHUTDOWN)
        return "KVM_EXIT_SHUTDOWN";
    if (exit_reason == KVM_EXIT_FAIL_ENTRY)
        return "KVM_EXIT_FAIL_ENTRY";
    if (exit_reason == KVM_EXIT_INTR)
        return "KVM_EXIT_INTR";
    if (exit_reason == KVM_EXIT_SET_TPR)
        return "KVM_EXIT_SET_TPR";
    if (exit_reason == KVM_EXIT_TPR_ACCESS)
        return "KVM_EXIT_TPR_ACCESS";
    if (exit_reason == KVM_EXIT_S390_SIEIC)
        return "KVM_EXIT_S390_SIEIC";
    if (exit_reason == KVM_EXIT_S390_RESET)
        return "KVM_EXIT_S390_RESET";
    if (exit_reason == KVM_EXIT_DCR)
        return "KVM_EXIT_DCR";
    if (exit_reason == KVM_EXIT_NMI)
        return "KVM_EXIT_NMI";
    if (exit_reason == KVM_EXIT_INTERNAL_ERROR)
        return "KVM_EXIT_INTERNAL_ERROR";
    if (exit_reason == KVM_EXIT_OSI)
        return "KVM_EXIT_OSI";
    if (exit_reason == KVM_EXIT_PAPR_HCALL)
        return "KVM_EXIT_PAPR_HCALL";
#ifdef KVM_EXIT_S390_UCONTROL
    if (exit_reason == KVM_EXIT_S390_UCONTROL)
        return "KVM_EXIT_S390_UCONTROL";
#endif
#ifdef KVM_EXIT_WATCHDOG
    if (exit_reason == KVM_EXIT_WATCHDOG)
        return "KVM_EXIT_WATCHDOG";
#endif
#ifdef KVM_EXIT_S390_TSCH
    if (exit_reason == KVM_EXIT_S390_TSCH)
        return "KVM_EXIT_S390_TSCH";
#endif
#ifdef KVM_EXIT_EPR
    if (exit_reason == KVM_EXIT_EPR)
        return "KVM_EXIT_EPR";
#endif
#ifdef KVM_EXIT_SYSTEM_EVENT
    if (exit_reason == KVM_EXIT_SYSTEM_EVENT)
        return "KVM_EXIT_SYSTEM_EVENT";
#endif
#ifdef KVM_EXIT_S390_STSI
    if (exit_reason == KVM_EXIT_S390_STSI)
        return "KVM_EXIT_S390_STSI";
#endif
#ifdef KVM_EXIT_IOAPIC_EOI
    if (exit_reason == KVM_EXIT_IOAPIC_EOI)
        return "KVM_EXIT_IOAPIC_EOI";
#endif
#ifdef KVM_EXIT_HYPERV
    if (exit_reason == KVM_EXIT_HYPERV)
        return "KVM_EXIT_HYPERV";
#endif
    return "? (unknown value)";
}

int main(void)
{
    uint8_t *guest_mempage;
    void *mem_vcpu;
    int kvmfd, vmfd, cpufd;
    int ret;
    size_t vcpu_mmap_size;
    const char *exit_reason_name;
    struct kvm_userspace_memory_region memreg;
    struct kvm_run *vcpu;
    struct kvm_regs regs;
    struct kvm_sregs sregs;

    /* Open KVM and check API version */
    kvmfd = open("/dev/kvm", 0);
    if (kvmfd == -1) {
        if (errno == ENOENT) {
            /* Fail nicely when there is no device */
            printf("/dev/kvm does not exist, exiting.\n");
            return 0;
        }
        perror("open(/dev/kvm)");
        return 1;
    }
    ret = ioctl(kvmfd, KVM_GET_API_VERSION, 0);
    if (ret < 0) {
        perror("ioctl(KVM_GET_API_VERSION)");
        return 1;
    } else if (ret != KVM_API_VERSION) {
        fprintf(
            stderr,
            "Error: incompatible kernel headers, /dev/kvm uses API %d but headers defines %d\n",
            ret, KVM_API_VERSION);
        return 1;
    }

    /* Display some extensions */
    printf("KVM extensions:\n");
    printf("  - KVM_CAP_NR_VCPUS (recommended max vcpus per vm): %d\n",
           ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS));
    printf("  - KVM_CAP_MAX_VCPUS (max vcpus per vm): %d\n",
           ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS));
    printf("  - KVM_CAP_NR_MEMSLOTS (max memory slots per vm): %d\n",
           ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS));
    printf("\n");

    /* Create a VM */
    vmfd = ioctl(kvmfd, KVM_CREATE_VM, 0);
    if (vmfd < 0) {
        perror("ioctl(KVM_CREATE_VM)");
        return 1;
    }

    /* Allocate 4KB for VM memory */
    guest_mempage = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guest_mempage == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(guest_mempage, 0, 0x1000);

    /* Map the memory to the top 32-bit memory */
    memreg.slot = 0;
    memreg.flags = 0;
    memreg.guest_phys_addr = 0xfffff000;
    memreg.memory_size = 0x1000;
    memreg.userspace_addr = (uint64_t)guest_mempage;
    if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
        perror("ioctl(KVM_SET_USER_MEMORY_REGION, code)");
        return 1;
    }

    /* Create a virtual CPU */
    cpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    if (vmfd < 0) {
        perror("ioctl(KVM_CREATE_VCPU)");
        return 1;
    }

    /* Map the CPU state */
    ret = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (ret == -1) {
        perror("ioctl(KVM_GET_VCPU_MMAP_SIZE)");
        return 1;
    }
    assert(ret > 0);
    vcpu_mmap_size = (size_t)ret;
    if (vcpu_mmap_size < sizeof(struct kvm_run)) {
        fprintf(stderr, "Internal KVM error: insufficient space given for struct kvm_run!\n");
        return 1;
    }
    printf("Allocating %d bytes for VCPU state (struct kvm_run is %u-byte long)\n",
           ret, (unsigned int)sizeof(struct kvm_run));
    mem_vcpu = mmap(0, vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpufd, 0);
    if (mem_vcpu == MAP_FAILED) {
        perror("mmap(VCPU)");
        return 1;
    }
    vcpu = (struct kvm_run *)mem_vcpu;

    /* Show inital register values */
    printf("Initial VCPU registers:\n");
    dump_registers(cpufd);

#if defined(__x86_64__) || defined(__i386__)
    /* Check that the registers hold their expected values */
    if (ioctl_read(cpufd, KVM_GET_REGS, &regs) < 0) {
        perror("ioctl(KVM_GET_REGS)");
        return 1;
    }
    if (ioctl_read(cpufd, KVM_GET_SREGS, &sregs) < 0) {
        perror("ioctl(KVM_GET_SREGS)");
        return 1;
    }
#    define check_initial_regval(reg, val, xfmt) \
        do { \
            if (reg != val) { \
                fprintf( \
                    stderr, \
                    "Unexpected initial register value: " #reg " = %#" xfmt ", not %#" xfmt "\n", \
                    (reg), (val)); \
                return 1; \
            } \
            printf("Initial " #reg " = %#" xfmt "\n", (reg)); \
        } while (0)
    /* Initialize registers */
    check_initial_regval(regs.rip, 0xfff0LLU, "llx");
    check_initial_regval(sregs.cs.base, 0xffff0000LLU, "llx");
    check_initial_regval(sregs.cs.selector, 0xf000, PRIx16);
    check_initial_regval(sregs.cs.type, 0xb, PRIx8);
    check_initial_regval(sregs.ds.base, 0LLU, "llx");
    check_initial_regval(sregs.ds.selector, 0, PRIx16);
    check_initial_regval(sregs.ds.type, 3, PRIx8);
#    undef check_initial_regval

    /* Write 16-bit x86 code:
        90          nop
        31 c0       xor %ax,%ax
        0f a2       cpuid
        f4          hlt
     */
    guest_mempage[0xff0] = 0x90;
    guest_mempage[0xff1] = 0x31;
    guest_mempage[0xff2] = 0xc0;
    guest_mempage[0xff3] = 0x0f;
    guest_mempage[0xff4] = 0xa2;
    guest_mempage[0xff5] = 0xf4;

    /* Configure CPUID */
    {
        struct {
            struct kvm_cpuid2 header;
            struct kvm_cpuid_entry2 entry;
        } kvm_cpuid_item;
        memset(&kvm_cpuid_item, 0, sizeof(kvm_cpuid_item));
        kvm_cpuid_item.header.nent = 1;
        kvm_cpuid_item.entry.eax = 1;
        kvm_cpuid_item.entry.ebx = 0x424d564b;
        kvm_cpuid_item.entry.edx = 0x43657361;
        kvm_cpuid_item.entry.ecx = 0x44495550;
        if (ioctl(cpufd, KVM_SET_CPUID2, &kvm_cpuid_item) < 0) {
            perror("ioctl(KVM_SET_CPUID2)");
            return 1;
        }
    }
#else
#    error Unsupported architecture
#endif
    printf("\n");

    /* Launch the CPU */
    if (ioctl(cpufd, KVM_RUN, 0) < 0) {
        perror("ioctl(KVM_RUN)");
        return 1;
    }

    /* Show the exit reason */
    exit_reason_name = get_exit_reason_name(vcpu->exit_reason);
    printf("VCPU exited with reason %u: %s\n", vcpu->exit_reason, exit_reason_name);
    if (vcpu->exit_reason == KVM_EXIT_FAIL_ENTRY) {
        printf("The VM fail entry reason is %#llx\n", vcpu->fail_entry.hardware_entry_failure_reason);
        return 1;
    }

#if defined(__x86_64__) || defined(__i386__)
    /* Get the final register values */
    if (ioctl_read(cpufd, KVM_GET_REGS, &regs) < 0) {
        perror("ioctl(KVM_GET_REGS)");
        return 1;
    }
    printf("... final rip is %#llx.\n", regs.rip);
    if (vcpu->exit_reason == KVM_EXIT_HLT && regs.rip == 0xfff6) {
        printf("CPUID(0) has been exectued. Result:\n");
        printf("    eax (max code) = %#llx\n", regs.rax);
        printf("    ebx = %#llx\n", regs.rbx);
        printf("    edx = %#llx\n", regs.rdx);
        printf("    ecx = %#llx\n", regs.rcx);
        printf("    vendor string: \"%.4s%.4s%.4s\"\n",
               (char *)&regs.rbx, (char *)&regs.rdx, (char *)&regs.rcx);
    }
#endif

    /* Clean up things */
    munmap(mem_vcpu, vcpu_mmap_size);
    close(cpufd);
    close(vmfd);
    close(kvmfd);
    munmap(guest_mempage, 0x1000);
    return 0;
}
