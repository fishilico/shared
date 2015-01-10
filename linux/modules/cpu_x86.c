/**
 * Print the value of x86-specific CPU registers and tables
 * These registers are:
 *  * the control registers (CR),
 *  * the model-specific registers (MSR),
 *  * interrupt and global descriptior tables,
 *  * ...
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/desc.h>
#include <asm/processor.h>
#include <asm/traps.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>

#define show_reg_bit(reg, bitname, bitnum, desc) \
	pr_info("  %2d (0x%08lx): %s %s (%s)\n", \
		bitnum, _BITUL(bitnum), \
		((reg) & _BITUL(bitnum)) ? "+" : "-", (bitname), (desc))

#define show_cr_bit(cr, crnum, bitname, desc) \
	show_reg_bit((cr), #bitname, X86_CR##crnum##_##bitname##_BIT, (desc))

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

	cr = read_cr3();
	pr_info("cr3 = 0x%08lx\n", cr);
	show_cr_bit(cr, 3, PWT, "Page Write Through");
	show_cr_bit(cr, 3, PCD, "Page Cache Disable");
	pr_info("  12...: 0x%08lx PDBR (Page Directory Base Register)\n", cr >> 12);

	cr = read_cr4_safe();
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
	show_cr_bit(cr, 4, SMEP, "enable SMEP support");
	show_cr_bit(cr, 4, SMAP, "enable SMAP support");

#ifdef CONFIG_X86_64
	cr = read_cr8();
	pr_info("cr8 = 0x%lx TPR (Task-Priority Register)\n", cr);
#endif
}

#define show_efer_bit(efer, bitname, desc) \
	show_reg_bit((efer), #bitname, _EFER_##bitname, (desc))

static void dump_x86_msr(void)
{
#ifdef CONFIG_X86_64
	unsigned long long msr;
	rdmsrl(MSR_FS_BASE, msr);
	pr_info("msr:fs_base = 0x%llx\n", msr);
	rdmsrl(MSR_GS_BASE, msr);
	pr_info("msr:gs_base = 0x%llx\n", msr);
	rdmsrl(MSR_KERNEL_GS_BASE, msr);
	pr_info("msr:kernel_gs_base = 0x%llx\n", msr);

	rdmsrl(MSR_EFER, msr);
	pr_info("msr:EFER = 0x%08llx (Extended Feature Enable Register)\n", msr);
	show_efer_bit(msr, SCE, "SYSCALL/SYSRET");
	show_efer_bit(msr, LME, "Long Mode Enable");
	show_efer_bit(msr, LMA, "Long Mode Active (read-only)");
	show_efer_bit(msr, NX, "No eXecute");
	show_efer_bit(msr, SVME, "Virtualization Enable");
	show_efer_bit(msr, LMSLE, "Long Mode Segment Limit Enable");
	show_efer_bit(msr, FFXSR, "Fast FXSAVE/FXRSTOR");

	rdmsrl(MSR_IA32_SYSENTER_CS, msr);
	pr_info("msr:ia32_sysenter_CS = 0x%llx\n", msr);
	rdmsrl(MSR_IA32_SYSENTER_ESP, msr);
	pr_info("msr:ia32_sysenter_ESP = 0x%llx\n", msr);
	rdmsrl(MSR_IA32_SYSENTER_EIP, msr);
	pr_info("msr:ia32_sysenter_EIP = 0x%llx (%pS)\n", msr, (void*)msr);

	/* http://wiki.osdev.org/SYSENTER
	 * Setup in /usr/src/linux/arch/x86/kernel/cpu/common.c
	 */
	rdmsrl(MSR_STAR, msr);
	pr_info("msr:star = user32 CS 0x%llx, kernel CS 0x%llx, EIP 0x%llx\n",
		msr >> 48, (msr >> 32) & 0xffff, msr & 0xffffffff);
	rdmsrl(MSR_LSTAR, msr); /* Long mode */
	pr_info("msr:lstar = 0x%llx (%pS)\n", msr, (void*)msr);
	rdmsrl(MSR_CSTAR, msr); /* Compatibility mode */
	pr_info("msr:cstar = 0x%llx (%pS)\n", msr, (void*)msr);
	rdmsrl(MSR_SYSCALL_MASK, msr);
	pr_info("msr:sfmask = 0x%llx\n", msr);
#endif
}

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

static void dump_x86_tables(void)
{
	unsigned int cpu, i, numentries;
	unsigned long tr;
	struct desc_ptr descp;

	compiletime_assert(sizeof(struct desc_struct) == 8,
		"struct desc_struct has changed size!");

	store_tr(tr);
	pr_info("TR: 0x%08lx (Task Register)\n", tr);

	native_store_gdt(&descp);
	pr_info("GDT: (Global Descriptor Table)\n");
	pr_info("  On current cpu: %pS limit %u\n", (void*)descp.address, descp.size);
	numentries = min(GDT_ENTRIES, (descp.size + 1) / 8);
	if (descp.size != GDT_ENTRIES * 8 - 1) {
		pr_warning("   Expected size differs: %u, using %u entries\n",
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
		descs = get_cpu_gdt_table(cpu);
		if (!descs)
			continue;
#endif
		pr_info("  CPU %u: %pS (%u entries)\n", cpu, descs, numentries);
		for (i = 0; i < numentries; i++) {
			unsigned int flags, base, limit, type;
			const char *comment = "";
			char type_str[5];
			if (!descs[i].a && !descs[i].b)
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
			flags = ((descs[i].b >> 8) & 0xf0ff);
			type = descs[i].type;
			pr_info("    %2u: base 0x%08x, limit 0x%x, flags 0x%04x%s\n",
				i, base, limit, flags, comment);
			/* Flags (http://wiki.osdev.org/Global_Descriptor_Table):
			 * Type: 4 bits: Executable, Direction bit (0=grows up), RW, Accessed
			 * DPL: Protection Level (ring 0 to 3)
			 * P: Segment is present
			 * AVL: Available for system (always set to 0)
			 * L: 0
			 * D: Operand Size (0 = 16 bit, 1 = 32 bit ?)
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
		(void*)descp.address, descp.size, numentries);
	if (descp.address) {
		gate_desc *idt;
		idt = (gate_desc*)descp.address;
		for (i = 0; i < NR_VECTORS && i < numentries; i++) {
			unsigned int type;
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
#ifdef CONFIG_HAVE_KVM
			else if (i == POSTED_INTR_VECTOR)
				comment = "Postr Intr Vector";
#endif
			else if (i == HYPERVISOR_CALLBACK_VECTOR)
				comment = "Hypervisor Callback Vector";
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
			type = idt[i].type;
			pr_info(" 0x%02x: seg 0x%x offset %p %s\n",
				i, gate_segment(idt[i]),
				(void *)gate_offset(idt[i]),
				comment);
			if (type == 5)
				type_str = " (task gate)";
			else if (type == 6)
				type_str = " (16-bit interrupt gate)";
			else if (type == 7)
				type_str = " (16-bit trap gate)";
			else if (type == 0xe)
				type_str = " (interrupt gate)";
			else if (type == 0xf)
				type_str = " (trap gate)";
			if (type != 0xe)
				pr_info("       type=0x%x%s\n", type, type_str);
#ifdef CONFIG_X86_32
			pr_cont(", s=%u", idt[i].s);
#else
			if (idt[i].ist) {
				const char *stack_str = "";
				if (idt[i].ist == DOUBLEFAULT_STACK)
					stack_str = " (double fault stack)";
				else if (idt[i].ist == NMI_STACK)
					stack_str = " (non-maskable interrupt stack)";
				else if (idt[i].ist == DEBUG_STACK)
					stack_str = " (debug stack)";
				else if (idt[i].ist == MCE_STACK)
					stack_str = " (machine check stack)";
				else if (idt[i].ist == N_EXCEPTION_STACKS)
					stack_str = " (N Exception stacks)";
#ifdef STACKFAULT_STACK
				else if (idt[i].ist == STACKFAULT_STACK)
					stack_str = " (stack fault stack)";
#endif
				pr_info("       ist=%u%s", idt[i].ist, stack_str);
			}
#endif
			if (idt[i].dpl != 0)
				pr_info("       dpl=%u\n", idt[i].dpl);
			if (idt[i].p != 1)
				pr_info("       p=%u\n", idt[i].p);
#ifdef CONFIG_KALLSYMS
			do {
				char sym[KSYM_SYMBOL_LEN], *plus;
				/* Use sprint_symbol to filter out non-zero offset because
				 * kallsyms_lookup_size_offset is not exported.
				 */
				sprint_symbol(sym, gate_offset(idt[i]));
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
