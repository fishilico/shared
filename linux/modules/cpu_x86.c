// SPDX-License-Identifier: GPL-2.0
/**
 * Print the value of x86-specific CPU registers and tables
 * These registers are:
 *  * the control registers (CR),
 *  * the model-specific registers (MSR),
 *  * interrupt and global descriptor tables,
 *  * ...
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/desc.h>
#include <asm/processor.h>
#include <asm/traps.h>

#include <linux/bug.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>

/* Add missing bitmask definitions which were added in recent kernels */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
#define X86_CR4_PKE 0x00400000
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
#define X86_CR4_SMXE 0x00004000
#define X86_CR4_FSGSBASE 0x00010000
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define X86_CR4_SMAP 0x00200000
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
#define X86_CR4_PCIDE 0x00020000
#endif

#define show_reg_bit(reg, bitname, bitmask, desc) \
	pr_info("  %2d (0x%08lx): %s %s (%s)\n", \
		ilog2(bitmask), (unsigned long)(bitmask), \
		((reg) & (bitmask)) ? "+" : "-", (bitname), (desc))

#define show_cr_bit(cr, crnum, bitname, desc) \
	show_reg_bit((cr), #bitname, X86_CR##crnum##_##bitname, (desc))

/**
 * Output example on x86_64:
 *      cr0 = 0x8005003b
 *         0 (0x00000001): + PE (Protection Enable)
 *         1 (0x00000002): + MP (Monitor Coprocessor)
 *         2 (0x00000004): - EM (Emulation)
 *         3 (0x00000008): + TS (Task Switched)
 *         4 (0x00000010): + ET (Extension Type)
 *         5 (0x00000020): + NE (Numeric Error)
 *        16 (0x00010000): + WP (Write Protect)
 *        18 (0x00040000): + AM (Alignment Mask)
 *        29 (0x20000000): - NW (Not Write-through)
 *        30 (0x40000000): - CD (Cache Disable)
 *        31 (0x80000000): + PG (Paging)
 *      cr2 = 0x0229e678 PFLA (Page Fault Linear Address)
 *      cr3 = 0x2b8c08000
 *         3 (0x00000008): - PWT (Page Write Through)
 *         4 (0x00000010): - PCD (Page Cache Disable)
 *        12...: 0x002b8c08 PDBR (Page Directory Base Register)
 *      cr4 = 0x000006f0
 *         0 (0x00000001): - VME (enable vm86 extensions)
 *         1 (0x00000002): - PVI (virtual interrupts flag enable)
 *         2 (0x00000004): - TSD (disable time stamp at ipl 3)
 *         3 (0x00000008): - DE (enable debugging extensions)
 *         4 (0x00000010): + PSE (enable page size extensions)
 *         5 (0x00000020): + PAE (enable physical address extensions)
 *         6 (0x00000040): + MCE (Machine check enable)
 *         7 (0x00000080): + PGE (enable global pages)
 *         8 (0x00000100): - PCE (enable performance counters at ipl 3)
 *         9 (0x00000200): + OSFXSR (enable fast FPU save and restore)
 *        10 (0x00000400): + OSXMMEXCPT (enable unmasked SSE exceptions)
 *        13 (0x00002000): - VMXE (enable VMX virtualization)
 *        14 (0x00004000): - SMXE (enable safer mode (TXT))
 *        16 (0x00010000): - FSGSBASE (enable RDWRFSGS support)
 *        17 (0x00020000): - PCIDE (enable PCID support)
 *        18 (0x00040000): - OSXSAVE (enable xsave and xrestore)
 *        20 (0x00100000): - SMEP (enable Supervisor Mode Execution Protection)
 *        21 (0x00200000): - SMAP (enable Supervisor Mode Access Prevention)
 *      cr8 = 0x0 TPR (Task-Priority Register)
 */
static void dump_x86_cr(void)
{
	unsigned long cr;

	cr = read_cr0();
	pr_info("cr0 = 0x%08lx\n", cr);
	show_cr_bit(cr, 0, PE, "Protection Enable");
	show_cr_bit(cr, 0, MP, "Monitor Coprocessor");
	show_cr_bit(cr, 0, EM, "Emulation");
	show_cr_bit(cr, 0, TS, "Task Switched");
	show_cr_bit(cr, 0, ET, "Extension Type");
	show_cr_bit(cr, 0, NE, "Numeric Error");
	show_cr_bit(cr, 0, WP, "Write Protect");
	show_cr_bit(cr, 0, AM, "Alignment Mask");
	show_cr_bit(cr, 0, NW, "Not Write-through");
	show_cr_bit(cr, 0, CD, "Cache Disable");
	show_cr_bit(cr, 0, PG, "Paging");

	cr = read_cr2();
	pr_info("cr2 = 0x%08lx PFLA (Page Fault Linear Address)\n", cr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	/* Commit 6c690ee1039b ("x86/mm: Split read_cr3() into read_cr3_pa() and
	 * __read_cr3()") renamed read_cr3() to __read_cr3() in Linux 4.13
	 */
	cr = __read_cr3();
#else
	cr = read_cr3();
#endif
	pr_info("cr3 = 0x%08lx\n", cr);
	show_cr_bit(cr, 3, PWT, "Page Write Through");
	show_cr_bit(cr, 3, PCD, "Page Cache Disable");
	pr_info("  12...: 0x%08lx PDBR (Page Directory Base Register)\n", cr >> 12);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	/* Commit 1ef55be16ed6 ("x86/asm: Get rid of __read_cr4_safe()") dropped
	 * __read_cr4_safe in favor of __read_cr4 in Linux 4.9
	 */
	cr = __read_cr4();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	/* Commit 1e02ce4cccdc ("x86: Store a per-cpu shadow copy of CR4")
	 * renamed read_cr4_safe to __read_cr4_safe in Linux 4.0
	 */
	cr = __read_cr4_safe();
#else
	cr = read_cr4_safe();
#endif
	pr_info("cr4 = 0x%08lx\n", cr);
	show_cr_bit(cr, 4, VME, "enable vm86 extensions");
	show_cr_bit(cr, 4, PVI, "virtual interrupts flag enable");
	show_cr_bit(cr, 4, TSD, "disable time stamp at ipl 3");
	show_cr_bit(cr, 4, DE, "enable debugging extensions");
	show_cr_bit(cr, 4, PSE, "enable page size extensions");
	show_cr_bit(cr, 4, PAE, "enable physical address extensions");
	show_cr_bit(cr, 4, MCE, "Machine check enable");
	show_cr_bit(cr, 4, PGE, "enable global pages");
	show_cr_bit(cr, 4, PCE, "enable performance counters at ipl 3");
	show_cr_bit(cr, 4, OSFXSR, "enable fast FPU save and restore");
	show_cr_bit(cr, 4, OSXMMEXCPT, "enable unmasked SSE exceptions");
	show_cr_bit(cr, 4, VMXE, "enable VMX virtualization");
	show_cr_bit(cr, 4, SMXE, "enable safer mode (TXT)");
	show_cr_bit(cr, 4, FSGSBASE, "enable RDWRFSGS support");
	show_cr_bit(cr, 4, PCIDE, "enable PCID support");
	show_cr_bit(cr, 4, OSXSAVE, "enable xsave and xrestore");
	show_cr_bit(cr, 4, SMEP, "enable Supervisor Mode Execution Protection");
	show_cr_bit(cr, 4, SMAP, "enable Supervisor Mode Access Prevention");
	show_cr_bit(cr, 4, PKE, "enable Protection Keys support");

#ifdef CONFIG_X86_64
	cr = read_cr8();
	pr_info("cr8 = 0x%lx TPR (Task-Priority Register)\n", cr);
#endif
}

#define show_efer_bit(efer, bitname, desc) \
	show_reg_bit((efer), #bitname, 1 << _EFER_##bitname, (desc))

/**
 * Output example on x86_64:
 *      msr:fs_base(0xc0000100) = 0x7f6ae5613700
 *      msr:gs_base(0xc0000101) = 0xffff88003fc00000
 *      msr:kernel_gs_base(0xc0000102) = 0x0
 *      msr:EFER(0xc0000080) = 0x00000d01 (Extended Feature Enable Register)
 *         0 (0x00000001): + SCE (SYSCALL/SYSRET)
 *         8 (0x00000100): + LME (Long Mode Enable)
 *        10 (0x00000400): + LMA (Long Mode Active (read-only))
 *        11 (0x00000800): + NX (No eXecute)
 *        12 (0x00001000): - SVME (Virtualization Enable)
 *        13 (0x00002000): - LMSLE (Long Mode Segment Limit Enable)
 *        14 (0x00004000): - FFXSR (Fast FXSAVE/FXRSTOR)
 *      msr:ia32_sysenter_CS(0x174) = 0x10
 *      msr:ia32_sysenter_ESP(0x175) = 0x0
 *      msr:ia32_sysenter_EIP(0x176) = 0xffffffff815a52f0 (entry_SYSENTER_compat+0x0/0x4e)
 *      msr:star(0xc0000081) = user32 CS 0x23, kernel CS 0x10, EIP 0x0
 *      msr:lstar(0xc0000082) = 0xffffffff815a2f50 (entry_SYSCALL_64+0x0/0x3)
 *      msr:cstar(0xc0000083) = 0xffffffff815a54f0 (entry_SYSCALL_compat+0x0/0x51)
 *      msr:sfmask(0xc0000084) = 0x47700
 */
static void dump_x86_msr(void)
{
#ifdef CONFIG_X86_64
	unsigned long long msr;

	rdmsrl(MSR_FS_BASE, msr);
	pr_info("msr:fs_base(0x%x) = 0x%llx\n", MSR_FS_BASE, msr);
	rdmsrl(MSR_GS_BASE, msr);
	pr_info("msr:gs_base(0x%x) = 0x%llx\n", MSR_GS_BASE, msr);
	rdmsrl(MSR_KERNEL_GS_BASE, msr);
	pr_info("msr:kernel_gs_base(0x%x) = 0x%llx\n", MSR_KERNEL_GS_BASE, msr);

	rdmsrl(MSR_EFER, msr);
	pr_info("msr:EFER(0x%x) = 0x%08llx (Extended Feature Enable Register)\n",
		MSR_EFER, msr);
	show_efer_bit(msr, SCE, "SYSCALL/SYSRET");
	show_efer_bit(msr, LME, "Long Mode Enable");
	show_efer_bit(msr, LMA, "Long Mode Active (read-only)");
	show_efer_bit(msr, NX, "No eXecute");
	show_efer_bit(msr, SVME, "Virtualization Enable");
	show_efer_bit(msr, LMSLE, "Long Mode Segment Limit Enable");
	show_efer_bit(msr, FFXSR, "Fast FXSAVE/FXRSTOR");

	rdmsrl(MSR_IA32_SYSENTER_CS, msr);
	pr_info("msr:ia32_sysenter_CS(0x%x) = 0x%llx\n", MSR_IA32_SYSENTER_CS, msr);
	rdmsrl(MSR_IA32_SYSENTER_ESP, msr);
	pr_info("msr:ia32_sysenter_ESP(0x%x) = 0x%llx\n", MSR_IA32_SYSENTER_ESP, msr);
	rdmsrl(MSR_IA32_SYSENTER_EIP, msr);
	pr_info("msr:ia32_sysenter_EIP(0x%x) = 0x%llx (%pS)\n",
		MSR_IA32_SYSENTER_EIP, msr, (void *)msr);

	/* http://wiki.osdev.org/SYSENTER
	 * Setup in /usr/src/linux/arch/x86/kernel/cpu/common.c
	 * STAR = Syscall Target
	 */
	rdmsrl(MSR_STAR, msr);
	pr_info("msr:star(0x%x) = user32 CS 0x%llx, kernel CS 0x%llx, EIP 0x%llx\n",
		MSR_STAR, msr >> 48, (msr >> 32) & 0xffff, msr & 0xffffffff);
	rdmsrl(MSR_LSTAR, msr); /* Long mode */
	pr_info("msr:lstar(0x%x) = 0x%llx (%pS)\n", MSR_LSTAR, msr, (void *)msr);
	rdmsrl(MSR_CSTAR, msr); /* Compatibility mode */
	pr_info("msr:cstar(0x%x) = 0x%llx (%pS)\n", MSR_CSTAR, msr, (void *)msr);
	rdmsrl(MSR_SYSCALL_MASK, msr);
	pr_info("msr:sfmask(0x%x) = 0x%llx\n", MSR_SYSCALL_MASK, msr);
#endif
}

/**
 * Output example on x86_64:
 *      CS = 0x0010 (kernel CS is 0x0010)
 *      DS = 0x0000 (current thread: 0x0000)
 *      ES = 0x0000 (current thread: 0x0000)
 *      FS = 0x0000 (current thread: 0x0000)
 *      GS = 0x0000 (current thread: 0x0000)
 *      SS = 0x0018 (kernel DS is 0x0018)
 *      TR: 0x00000040 (Task Register)
 */
static void dump_x86_segments(void)
{
	unsigned long seg;

	savesegment(cs, seg);
	pr_info("CS = 0x%04lx (kernel CS is 0x%04x)\n", seg, __KERNEL_CS);
	savesegment(ds, seg);
	pr_info("DS = 0x%04lx (current thread: 0x%04x)\n", seg, current->thread.ds);
	savesegment(es, seg);
	pr_info("ES = 0x%04lx (current thread: 0x%04x)\n", seg, current->thread.es);
	savesegment(fs, seg);
	pr_info("FS = 0x%04lx (current thread: 0x%04x)\n", seg, current->thread.fsindex);
	savesegment(gs, seg);
	pr_info("GS = 0x%04lx (current thread: 0x%04x)\n", seg, current->thread.gsindex);
	savesegment(ss, seg);
	pr_info("SS = 0x%04lx (kernel DS is 0x%04x)\n", seg, __KERNEL_DS);
}

/**
 * Output example on x86_64:
 *      GDT: (Global Descriptor Table)
 *        On current cpu: 0xffff88041fbc9000 limit 127
 *        CPU 0: 0xffff88041fa09000 (16 entries)
 *        CPU 0: 0xffff880471c09000 (16 entries)
 *           1: <ff ff 00 00 00 9b cf 00>
 *              base 0x00000000, limit 0xfffff, flags 0xc09b (Kernel32 CS)
 *              type=0xb (C-RA), s=1, dpl=0, p=1, avl=0, l=0, d=1, g=1
 *           2: <ff ff 00 00 00 9b af 00>
 *              base 0x00000000, limit 0xfffff, flags 0xa09b (Kernel CS)
 *              type=0xb (C-RA), s=1, dpl=0, p=1, avl=0, l=1, d=0, g=1
 *           3: <ff ff 00 00 00 93 cf 00>
 *              base 0x00000000, limit 0xfffff, flags 0xc093 (Kernel DS)
 *              type=0x3 (D-WA), s=1, dpl=0, p=1, avl=0, l=0, d=1, g=1
 *           4: <ff ff 00 00 00 fb cf 00>
 *              base 0x00000000, limit 0xfffff, flags 0xc0fb (Default user32 CS)
 *              type=0xb (C-RA), s=1, dpl=3, p=1, avl=0, l=0, d=1, g=1
 *           5: <ff ff 00 00 00 f3 cf 00>
 *              base 0x00000000, limit 0xfffff, flags 0xc0f3 (Default user DS)
 *              type=0x3 (D-WA), s=1, dpl=3, p=1, avl=0, l=0, d=1, g=1
 *           6: <ff ff 00 00 00 fb af 00>
 *              base 0x00000000, limit 0xfffff, flags 0xa0fb (Default user CS)
 *              type=0xb (C-RA), s=1, dpl=3, p=1, avl=0, l=1, d=0, g=1
 *           8: <87 20 40 27 a1 8b 00 1f>
 *              base 0x1fa12740, limit 0x2087, flags 0x008b (TSS, Task State Segment)
 *              type=0xb (C-RA), s=0, dpl=0, p=1, avl=0, l=0, d=0, g=0
 *           9: <04 88 ff ff 00 00 00 00>
 *              base 0x0000ffff, limit 0x8804, flags 0x0000 (TSS+1)
 *              type=0x0 (D---), s=0, dpl=0, p=0, avl=0, l=0, d=0, g=0
 *          15: <00 00 00 00 00 f5 40 00>
 *              base 0x00000000, limit 0x0, flags 0x40f5 (per CPU)
 *              type=0x5 (Dv-A), s=1, dpl=3, p=1, avl=0, l=0, d=1, g=0
 *      IDT: 0xffffffffff57a000 limit 4095 (Interrupt Descriptor Table, 256 entries)
 *       0x00: seg 0x10 offset ffffffff815a4810 Divide by Zero
 *             Sym: divide_error
 *       0x01: seg 0x10 offset ffffffff815a4cb0 Debug
 *             ist=3 (debug stack)
 *             Sym: debug
 *       0x02: seg 0x10 offset ffffffff815a5140 Non-maskable Interrupt
 *             ist=2 (non-maskable interrupt stack)
 *             Sym: nmi
 *       0x03: seg 0x10 offset ffffffff815a4d20 Break Point
 *             ist=3 (debug stack)
 *             dpl=3
 *             Sym: int3
 *       0x04: seg 0x10 offset ffffffff815a4840 Overflow
 *             dpl=3
 *             Sym: overflow
 *       0x05: seg 0x10 offset ffffffff815a4870 Bound Range Exceeded
 *             Sym: bounds
 *       0x06: seg 0x10 offset ffffffff815a48a0 Invalid Opcode
 *             Sym: invalid_op
 *       0x07: seg 0x10 offset ffffffff815a48d0 Device Not Available
 *             Sym: device_not_available
 *       0x08: seg 0x10 offset ffffffff815a4900 Double Fault
 *             ist=1 (double fault stack)
 *             Sym: double_fault
 *       0x09: seg 0x10 offset ffffffff815a4930 Coprocessor Segment Overrun
 *             Sym: coprocessor_segment_overrun
 *       0x0a: seg 0x10 offset ffffffff815a4960 Invalid TSS
 *             Sym: invalid_TSS
 *       0x0b: seg 0x10 offset ffffffff815a4990 Segment Not Present
 *             Sym: segment_not_present
 *       0x0c: seg 0x10 offset ffffffff815a4d90 Stack Segment Fault
 *             Sym: stack_segment
 *       0x0d: seg 0x10 offset ffffffff815a4e50 General Protection Fault
 *             Sym: general_protection
 *       0x0e: seg 0x10 offset ffffffff815a4eb0 Page Fault
 *             Sym: page_fault
 *       0x0f: seg 0x10 offset ffffffff815a49c0 Spurious Interrupt
 *             Sym: spurious_interrupt_bug
 *       0x10: seg 0x10 offset ffffffff815a49f0 x87 Floating-Point Exception
 *             Sym: coprocessor_error
 *       0x11: seg 0x10 offset ffffffff815a4a20 Alignment Check
 *             Sym: alignment_check
 *       0x12: seg 0x10 offset ffffffff815a4f10 Machine Check
 *             ist=4 (machine check stack)
 *             Sym: machine_check
 *       0x13: seg 0x10 offset ffffffff815a4a50 SIMD Floating-Point Exception
 *             Sym: simd_coprocessor_error
 *       0x20: seg 0x10 offset ffffffff815a3cb0 IRET Exception
 *             Sym: irq_move_cleanup_interrupt
 *       0x80: seg 0x10 offset ffffffff815a5700 Syscall Vector
 *             dpl=3
 *             Sym: entry_INT80_compat
 *       0xef: seg 0x10 offset ffffffff815a3d90 Local Timer Vector
 *             Sym: apic_timer_interrupt
 *       0xf2: seg 0x10 offset ffffffff815a3f50 Postr Intr Vector
 *             Sym: kvm_posted_intr_ipi
 *       0xf3: seg 0x10 offset ffffffff815a4650 Hypervisor Callback Vector
 *             Sym: spurious_interrupt
 *       0xf5: seg 0x10 offset ffffffff815a4650 UV Bau Message
 *             Sym: spurious_interrupt
 *       0xf6: seg 0x10 offset ffffffff815a4730 IRQ Work Vector
 *             Sym: irq_work_interrupt
 *       0xf7: seg 0x10 offset ffffffff815a3e70 x86 Plateform IPI Vector
 *             Sym: x86_platform_ipi
 *       0xf8: seg 0x10 offset ffffffff815a3d20 Reboot Vector
 *             Sym: reboot_interrupt
 *       0xf9: seg 0x10 offset ffffffff815a4030 Threshold APIC Vector
 *             Sym: threshold_interrupt
 *       0xfa: seg 0x10 offset ffffffff815a41f0 Thermal APIC Vector
 *             Sym: thermal_interrupt
 *       0xfb: seg 0x10 offset ffffffff815a42d0 Call Function Single Vector
 *             Sym: call_function_single_interrupt
 *       0xfc: seg 0x10 offset ffffffff815a43b0 Call Function Vector
 *             Sym: call_function_interrupt
 *       0xfd: seg 0x10 offset ffffffff815a4490 Reschedule Vector
 *             Sym: reschedule_interrupt
 *       0xfe: seg 0x10 offset ffffffff815a4570 Error APIC Vector
 *             Sym: error_interrupt
 *       0xff: seg 0x10 offset ffffffff815a4650 Spurious APIC Vector
 *             Sym: spurious_interrupt
 */
static void dump_x86_tables(void)
{
	unsigned int cpu, i, numentries;
	unsigned long tr;
	struct desc_ptr descp;

	BUILD_BUG_ON(sizeof(struct desc_struct) != 8);

	store_tr(tr);
	pr_info("TR: 0x%08lx (Task Register)\n", tr);

	native_store_gdt(&descp);
	pr_info("GDT: (Global Descriptor Table)\n");
	pr_info("  On current cpu: %pS limit %u\n", (void *)descp.address, descp.size);
	numentries = min(GDT_ENTRIES, (descp.size + 1) / 8);
	if (descp.size != GDT_ENTRIES * 8 - 1) {
		pr_warn("   Expected size differs: %u, using %u entries\n",
			GDT_ENTRIES * 8 - 1, numentries);
	}
	/* Dump GDT tables. Expected result in written in
	 * /usr/src/linux/arch/x86/kernel/cpu/common.c
	 */
#if defined(CONFIG_GRKERNSEC) && defined(CONFIG_X86_64)
	/* as grsec patch doesn't export cpu_gdt_table symbol in
	 * arch/x86/kernel/x8664_ksyms_64.c, contrary to i386_ksyms_32.c,
	 * only use the gdt of the current cpu
	 */
	if (true) {
		struct desc_struct *descs;

		cpu = smp_processor_id();
		descs = (struct desc_struct *)descp.address;
#else
	for_each_possible_cpu(cpu) {
		struct desc_struct *descs;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
		/* Commit 69218e47994d ("x86: Remap GDT tables in the fixmap section")
		 * replaced get_cpu_gdt_table() with get_cpu_gdt_rw() and
		 * get_cpu_gdt_ro() in Linux 4.12
		 */
		descs = get_cpu_gdt_ro(cpu);
#else
		descs = get_cpu_gdt_table(cpu);
#endif
		if (!descs)
			continue;
#endif
		pr_info("  CPU %u: %pS (%u entries)\n", cpu, descs, numentries);
		for (i = 0; i < numentries; i++) {
			unsigned int flags, base, limit, type;
			const char *comment = "";
			char type_str[5];

			BUILD_BUG_ON(sizeof(descs[i]) != 8);
			if (!memcmp(&descs[i], "\0\0\0\0\0\0\0\0", 8))
				continue;
			if (i == GDT_ENTRY_KERNEL_CS)
				comment = " (Kernel CS)";
#ifdef GDT_ENTRY_KERNEL32_CS
			else if (i == GDT_ENTRY_KERNEL32_CS)
				comment = " (Kernel32 CS)";
#endif
			else if (i == GDT_ENTRY_KERNEL_DS)
				comment = " (Kernel DS)";
			else if (i == GDT_ENTRY_DEFAULT_USER_CS)
				comment = " (Default user CS)";
#ifdef GDT_ENTRY_DEFAULT_USER32_CS
			else if (i == GDT_ENTRY_DEFAULT_USER32_CS)
				comment = " (Default user32 CS)";
#endif
			else if (i == GDT_ENTRY_DEFAULT_USER_DS)
				comment = " (Default user DS)";
			else if (i == GDT_ENTRY_TSS)
				comment = " (TSS, Task State Segment)";
			else if (!IS_ENABLED(CONFIG_X86_32) && i == GDT_ENTRY_TSS + 1)
				comment = " (TSS+1)";
			else if (i == GDT_ENTRY_LDT)
				comment = " (LDT, Local Descriptor Table)";
			else if (!IS_ENABLED(CONFIG_X86_32) && i == GDT_ENTRY_LDT + 1)
				comment = " (LDT+1)";
#ifdef GDT_ENTRY_PER_CPU
			else if (i == GDT_ENTRY_PER_CPU)
				comment = " (per CPU)";
#endif
			base = get_desc_base(&descs[i]);
			limit = get_desc_limit(&descs[i]);
			flags = (((const u32 *)&descs[i])[1] >> 8) & 0xf0ff;
			type = descs[i].type;
			pr_info("    %2u: <%8ph>\n", i, &descs[i]);
			pr_info("        base 0x%08x, limit 0x%x, flags 0x%04x%s\n",
				base, limit, flags, comment);
			/* Flags (http://wiki.osdev.org/Global_Descriptor_Table):
			 * Type: 4 bits: Executable, Direction bit (0=grows up), RW, Accessed
			 * DPL: Protection Level (ring 0 to 3)
			 * P: Segment is present
			 * AVL: Available for system (always set to 0)
			 * L: Long mode (1 for 64-bit code segment)
			 * D: Operand Size (if L=0: 0 = 16 bit, 1 = 32 bit)
			 * G: Granularity (0 = 1 Byte, 1 = 4k Byte)
			 */
			type_str[0] = (type & 8) ? 'C' : 'D'; /* Code vs. Data */
			type_str[1] = (type & 4) ? 'v' : '-'; /* Grows up or down */
			type_str[2] = (type & 2) ? ((type & 8) ? 'R' : 'W') : '-'; /* Code: RX vs X, Data: RW vs R- */
			type_str[3] = (type & 1) ? 'A' : '-';
			type_str[4] = '\0';
			pr_info("        type=0x%x (%s), s=%u, dpl=%u, p=%u, avl=%u, l=%u, d=%u, g=%u\n",
				type, type_str, descs[i].s, descs[i].dpl, descs[i].p,
				descs[i].avl, descs[i].l, descs[i].d, descs[i].g);
		}
	}

	store_idt(&descp);
	numentries = (descp.size + 1) / sizeof(gate_desc);
	pr_info("IDT: %pS limit %u (Interrupt Descriptor Table, %u entries)\n",
		(void *)descp.address, descp.size, numentries);
	if (descp.address) {
		gate_desc *idt;

		idt = (gate_desc *)descp.address;
		for (i = 0; i < NR_VECTORS && i < numentries; i++) {
			unsigned int idt_type, idt_ist, idt_dpl, idt_p;
			unsigned long idt_segment, idt_offset;
			const char *comment = "", *type_str = "";

			/* /usr/src/linux/arch/x86/include/asm/traps.h
			 * /usr/src/linux/arch/x86/include/asm/irq_vectors.h
			 * and /usr/src/linux/arch/x86/kernel/traps.c
			 */
			if (i == X86_TRAP_DE)
				comment = "Divide by Zero";
			else if (i == X86_TRAP_DB)
				comment = "Debug";
			else if (i == X86_TRAP_NMI)
				comment = "Non-maskable Interrupt";
			else if (i == X86_TRAP_BP)
				comment = "Break Point";
			else if (i == X86_TRAP_OF)
				comment = "Overflow";
			else if (i == X86_TRAP_BR)
				comment = "Bound Range Exceeded";
			else if (i == X86_TRAP_UD)
				comment = "Invalid Opcode";
			else if (i == X86_TRAP_NM)
				comment = "Device Not Available";
			else if (i == X86_TRAP_DF)
				comment = "Double Fault";
			else if (i == X86_TRAP_OLD_MF)
				comment = "Coprocessor Segment Overrun";
			else if (i == X86_TRAP_TS)
				comment = "Invalid TSS";
			else if (i == X86_TRAP_NP)
				comment = "Segment Not Present";
			else if (i == X86_TRAP_SS)
				comment = "Stack Segment Fault";
			else if (i == X86_TRAP_GP)
				comment = "General Protection Fault";
			else if (i == X86_TRAP_PF)
				comment = "Page Fault";
			else if (i == X86_TRAP_SPURIOUS)
				comment = "Spurious Interrupt";
			else if (i == X86_TRAP_MF)
				comment = "x87 Floating-Point Exception";
			else if (i == X86_TRAP_AC)
				comment = "Alignment Check";
			else if (i == X86_TRAP_MC)
				comment = "Machine Check";
			else if (i == X86_TRAP_XF)
				comment = "SIMD Floating-Point Exception";
			else if (i == X86_TRAP_IRET)
				comment = "IRET Exception";
			else if (i == FIRST_EXTERNAL_VECTOR)
				comment = "First External Vector";
			else if (i == IA32_SYSCALL_VECTOR)
				comment = "Syscall Vector";
			else if (i == LOCAL_TIMER_VECTOR)
				comment = "Local Timer Vector";
#if defined(CONFIG_HAVE_KVM) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
			/* Introduced by commit d78f2664832f
			 * ("KVM: VMX: Register a new IPI for posted interrupt")
			 */
			else if (i == POSTED_INTR_VECTOR)
				comment = "Postr Intr Vector";
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
			/* Introduced by commit bc2b0331e077
			 * ("X86: Handle Hyper-V vmbus interrupts as special hypervisor interrupts")
			 */
			else if (i == HYPERVISOR_CALLBACK_VECTOR)
				comment = "Hypervisor Callback Vector";
#endif
			else if (i == UV_BAU_MESSAGE)
				comment = "UV Bau Message";
			else if (i == IRQ_WORK_VECTOR)
				comment = "IRQ Work Vector";
			else if (i == X86_PLATFORM_IPI_VECTOR)
				comment = "x86 Plateform IPI Vector";
			else if (i == REBOOT_VECTOR)
				comment = "Reboot Vector";
			else if (i == THRESHOLD_APIC_VECTOR)
				comment = "Threshold APIC Vector";
			else if (i == THERMAL_APIC_VECTOR)
				comment = "Thermal APIC Vector";
			else if (i == CALL_FUNCTION_SINGLE_VECTOR)
				comment = "Call Function Single Vector";
			else if (i == CALL_FUNCTION_VECTOR)
				comment = "Call Function Vector";
			else if (i == RESCHEDULE_VECTOR)
				comment = "Reschedule Vector";
			else if (i == ERROR_APIC_VECTOR)
				comment = "Error APIC Vector";
			else if (i == SPURIOUS_APIC_VECTOR)
				comment = "Spurious APIC Vector";

			/* Skip unknown vectors */
			if (!comment[0])
				continue;

			/* http://wiki.osdev.org/Interrupts_Descriptor_Table */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
			/* Commit 64b163fab684 ("x86/idt: Unify gate_struct
			 * handling for 32/64-bit kernels") grouped the
			 * bitfields into a new struct.
			 */
			idt_type = idt[i].bits.type;
			idt_ist = idt[i].bits.ist;
			idt_dpl = idt[i].bits.dpl;
			idt_p = idt[i].bits.p;
			idt_segment = gate_segment(&idt[i]);
			idt_offset = gate_offset(&idt[i]);
#else
			idt_type = idt[i].type;
			idt_ist = idt[i].ist;
			idt_dpl = idt[i].dpl;
			idt_p = idt[i].p;
			idt_segment = gate_segment(idt[i]);
			idt_offset = gate_offset(idt[i]);
#endif
			pr_info(" 0x%02x: seg 0x%lx offset %p %s\n",
				i, idt_segment, (void *)idt_offset, comment);
			if (idt_type == 5)
				type_str = " (task gate)";
			else if (idt_type == 6)
				type_str = " (16-bit interrupt gate)";
			else if (idt_type == 7)
				type_str = " (16-bit trap gate)";
			else if (idt_type == 0xe)
				type_str = " (interrupt gate)";
			else if (idt_type == 0xf)
				type_str = " (trap gate)";
			if (idt_type != 0xe)
				pr_info("       type=0x%x%s\n", idt_type, type_str);
#ifdef CONFIG_X86_32
			pr_info("       s=%u\n", idt[i].s);
#else
			if (idt_ist) {
				const char *stack_str = "";

				if (idt_ist == DOUBLEFAULT_STACK)
					stack_str = " (double fault stack)";
				else if (idt_ist == NMI_STACK)
					stack_str = " (non-maskable interrupt stack)";
				else if (idt_ist == DEBUG_STACK)
					stack_str = " (debug stack)";
				else if (idt_ist == MCE_STACK)
					stack_str = " (machine check stack)";
				else if (idt_ist == N_EXCEPTION_STACKS)
					stack_str = " (N Exception stacks)";
#ifdef STACKFAULT_STACK
				else if (idt_ist == STACKFAULT_STACK)
					stack_str = " (stack fault stack)";
#endif
				pr_info("       ist=%u%s", idt_ist, stack_str);
			}
#endif
			if (idt_dpl != 0)
				pr_info("       dpl=%u\n", idt_dpl);
			if (idt_p != 1)
				pr_info("       p=%u\n", idt_p);
#ifdef CONFIG_KALLSYMS
			do {
				char sym[KSYM_SYMBOL_LEN], *plus;
				/* Use sprint_symbol to filter out non-zero offset because
				 * kallsyms_lookup_size_offset is not exported.
				 */
				sprint_symbol(sym, idt_offset);
				if (sym[0] == '\0' || (sym[0] == '0' && sym[1] == 'x'))
					break;
				plus = strchr(sym, '+');
				if (plus && plus[1] == '0' && plus[2] == 'x') {
					/* Remove "+0x0" offset */
					if (plus[3] == '0' && plus[4] == '/')
						*plus = '\0';
				}
				pr_info("       Sym: %s\n", sym);
			} while (0);
#endif
		}
	}
}

static int __init cpu_x86_init(void)
{
	pr_info("Current CPU: %u\n", smp_processor_id());
	dump_x86_cr();
	dump_x86_msr();
	dump_x86_segments();
	dump_x86_tables();
	return 0;
}

static void __exit cpu_x86_exit(void)
{
}

module_init(cpu_x86_init);
module_exit(cpu_x86_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Iooss");
MODULE_DESCRIPTION("Print the value of x86-specific CPU registers and tables");
