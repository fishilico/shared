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

/* Add Intel Key Locker (bit 18) defined in
 * https://www.intel.com/content/www/us/en/develop/download/intel-key-locker-specification.html
 */
#define X86_CR4_KL 0x00080000
#define X86_CR4_UINTR 0x02000000
#define X86_CR4_PKS 0x01000000
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
/* Introduced in 6.19
 * "x86/cpufeatures: Enumerate the LASS feature bits"
 * https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7baadd463e147fdcb6d3a091d85e23f89832569c
 */
#define X86_CR4_LASS 0x08000000
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
/* Introduced in 6.9
 * "x86/cpu: Add X86_CR4_FRED macro"
 * https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ff45746fbf005f96e42bea466698e3fdbf926013
 */
#define X86_CR4_FRED 0x100000000
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
/* Introduced in 6.4
 * "x86: CPUID and CR3/CR4 flags for Linear Address Masking"
 * https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6449dcb0cac738219d13c618af7fd8664735f99d
 */
#define X86_CR3_LAM_U57 0x2000000000000000
#define X86_CR3_LAM_U48 0x4000000000000000
#define X86_CR4_LAM_SUP 0x10000000
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
/* Introduced in 6.3
 * "x86/cpu: Support AMD Automatic IBRS"
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e7862eda309ecfccc36bb5558d937ed3ace07f3f
 */
#define _EFER_AUTOIBRS 21
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
#define X86_CR4_CET 0x00800000
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#define X86_CR4_UMIP 0x00000800
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 11)
/* Introduced in 4.15, backported in 4.14.11 LTS:
 * https://elixir.bootlin.com/linux/v4.14.11/source/arch/x86/include/uapi/asm/processor-flags.h#L85
 * and in 4.9.75 LTS
 * https://elixir.bootlin.com/linux/v4.9.75/source/arch/x86/include/uapi/asm/processor-flags.h
 * and in 3.16.53 LTS
 * https://elixir.bootlin.com/linux/v3.16.53/source/arch/x86/include/uapi/asm/processor-flags.h
 * and many more LTS versions
 */
#ifndef X86_CR3_PCID_NOFLUSH
#define X86_CR3_PCID_NOFLUSH 0x8000000000000000
#endif
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define X86_CR4_LA57 0x00001000
#endif
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

/* Add EFER bits defined in Little Kernel, for AMD CPU
 * https://github.com/littlekernel/lk/blob/30dc320054f70910e1c1ee40a6948ee99672acec/arch/x86/include/arch/x86.h
 */
#define _EFER_TCE 15
#define _EFER_MCOMMIT 17
#define _EFER_INTWB 18
#define _EFER_UAIE 20

#define show_reg_bit(reg, bitname, bitmask, desc) \
	pr_info("  %2d (0x%08lx): %s %s (%s)\n", \
		ilog2(bitmask), (unsigned long)(bitmask), \
		((reg) & (bitmask)) ? "+" : "-", (bitname), (desc))

#define show_cr_bit(cr, crnum, bitname, desc) \
	show_reg_bit((cr), #bitname, X86_CR##crnum##_##bitname, (desc))

#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	/* Commit 83b584d9c6a1 ("x86/paravirt: Drop {read,write}_cr8() hooks")
	 * removed read_cr8() in Linux 5.4
	 */
	static inline unsigned long read_cr8(void)
	{
		unsigned long cr8;

		asm volatile("movq %%cr8,%0" : "=r" (cr8));
		return cr8;
	}
#endif

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
 *      cr2 = 0x0229e678 PFLA (Page Fault Linear Address)[54154.124922] cpu_x86: cr3 = 0x5b8904006
 *      cr3 = 0x5b8904006
 *        0...11: 0x006 PCID (Process-Context Identifier)
 *         3 (0x00000008): - PWT (Page Write Through)
 *         4 (0x00000010): - PCD (Page Cache Disable)
 *        12...: 0x005b8904 PDBR (Page Directory Base Register)
 *        61 (0x2000000000000000): - LAM_U57 (Activate LAM for userspace, 62:57 bits masked)
 *        62 (0x4000000000000000): - LAM_U48 (Activate LAM for userspace, 62:48 bits masked)
 *        63 (0x8000000000000000): - PCID_NOFLUSH (Preserve old PCID)
 *      cr4 = 0x00770ee0
 *         0 (0x00000001): - VME (enable vm86 extensions)
 *         1 (0x00000002): - PVI (virtual interrupts flag enable)
 *         2 (0x00000004): - TSD (disable time stamp at ipl 3)
 *         3 (0x00000008): - DE (enable debugging extensions)
 *         4 (0x00000010): - PSE (enable page size extensions)
 *         5 (0x00000020): + PAE (enable physical address extensions)
 *         6 (0x00000040): + MCE (Machine check enable)
 *         7 (0x00000080): + PGE (enable global pages)
 *         8 (0x00000100): - PCE (enable performance counters at ipl 3)
 *         9 (0x00000200): + OSFXSR (enable fast FPU save and restore)
 *        10 (0x00000400): + OSXMMEXCPT (enable unmasked SSE exceptions)
 *        11 (0x00000800): + UMIP (enable User-Mode Instruction Prevention (UMIP) support)
 *        12 (0x00001000): - LA57 (enable 5-level page tables)
 *        13 (0x00002000): - VMXE (enable Virtual Machine Extensions)
 *        14 (0x00004000): - SMXE (enable Safer Mode Extensions (TXT))
 *        16 (0x00010000): + FSGSBASE (enable RDWRFSGS instructions support)
 *        17 (0x00020000): + PCIDE (enable Process Context ID support)
 *        18 (0x00040000): + OSXSAVE (enable XSAVE and XRESTORE instructions)
 *        19 (0x00080000): - KL (enable Intel Key Locker)
 *        20 (0x00100000): + SMEP (enable Supervisor Mode Execution Protection)
 *        21 (0x00200000): + SMAP (enable Supervisor Mode Access Prevention)
 *        22 (0x00400000): + PKE (enable Protection Keys support)
 *        23 (0x00800000): - CET (enable Control-flow Enforcement Technology)
 *        24 (0x01000000): - PKS (enable Protection Keys for Supervisor-Mode Pages)
 *        25 (0x02000000): - UINTR (enable User Interrupts)
 *        27 (0x08000000): - LASS (enable Linear Address Space Separation)
 *        28 (0x10000000): - LAM_SUP (Linear Address Masking (LAM) for supervisor pointers)
 *        32 (0x100000000): - FRED (enable Flexible Return and Event Delivery (FRED))
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
	pr_info("  0...11: 0x%03lx PCID (Process-Context Identifier)\n", cr & 0xfff);
	show_cr_bit(cr, 3, PWT, "Page Write Through");
	show_cr_bit(cr, 3, PCD, "Page Cache Disable");
	pr_info("  12...: 0x%08lx PDBR (Page Directory Base Register)\n", cr >> 12);
	show_cr_bit(cr, 3, LAM_U57, "Activate LAM for userspace, 62:57 bits masked");
	show_cr_bit(cr, 3, LAM_U48, "Activate LAM for userspace, 62:48 bits masked");
	show_cr_bit(cr, 3, PCID_NOFLUSH, "Preserve old PCID");

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
	show_cr_bit(cr, 4, UMIP, "enable User-Mode Instruction Prevention (UMIP) support");
	show_cr_bit(cr, 4, LA57, "enable 5-level page tables");
	show_cr_bit(cr, 4, VMXE, "enable Virtual Machine Extensions");
	show_cr_bit(cr, 4, SMXE, "enable Safer Mode Extensions (TXT)");
	show_cr_bit(cr, 4, FSGSBASE, "enable RDWRFSGS instructions support");
	show_cr_bit(cr, 4, PCIDE, "enable Process Context ID support");
	show_cr_bit(cr, 4, OSXSAVE, "enable XSAVE and XRESTORE instructions");
	show_cr_bit(cr, 4, KL, "enable Intel Key Locker");
	show_cr_bit(cr, 4, SMEP, "enable Supervisor Mode Execution Protection");
	show_cr_bit(cr, 4, SMAP, "enable Supervisor Mode Access Prevention");
	show_cr_bit(cr, 4, PKE, "enable Protection Keys support");
	show_cr_bit(cr, 4, CET, "enable Control-flow Enforcement Technology");
	show_cr_bit(cr, 4, PKS, "enable Protection Keys for Supervisor-Mode Pages");
	show_cr_bit(cr, 4, UINTR, "enable User Interrupts");
	show_cr_bit(cr, 4, LASS, "enable Linear Address Space Separation");
	show_cr_bit(cr, 4, LAM_SUP, "Linear Address Masking (LAM) for supervisor pointers");
	show_cr_bit(cr, 4, FRED, "enable Flexible Return and Event Delivery (FRED)");

#ifdef CONFIG_X86_64
	cr = read_cr8();
	pr_info("cr8 = 0x%lx TPR (Task-Priority Register)\n", cr);
#endif
}

#define show_efer_bit(efer, bitname, desc) \
	show_reg_bit((efer), #bitname, 1 << _EFER_##bitname, (desc))

/**
 * Output example on x86_64:
 *      msr:fs_base(0xc0000100) = 0x7fdb12083740
 *      msr:gs_base(0xc0000101) = 0xffff9daffba80000
 *      msr:kernel_gs_base(0xc0000102) = 0x0
 *      msr:EFER(0xc0000080) = 0x00000d01 (Extended Feature Enable Register)
 *         0 (0x00000001): + SCE (SYSCALL/SYSRET)
 *         8 (0x00000100): + LME (Long Mode Enable)
 *        10 (0x00000400): + LMA (Long Mode Active (read-only))
 *        11 (0x00000800): + NX (No eXecute)
 *        12 (0x00001000): - SVME (Virtualization Enable)
 *        13 (0x00002000): - LMSLE (Long Mode Segment Limit Enable)
 *        14 (0x00004000): - FFXSR (Fast FXSAVE/FXRSTOR)
 *        15 (0x00008000): - TCE (Translation Cache Extension)
 *        17 (0x00020000): - MCOMMIT (MCOMMIT instruction Enable)
 *        18 (0x00040000): - INTWB (Interrupt WBINVD/WBNOINVD Enable)
 *        20 (0x00100000): - UAIE (Upper Address Ignore Enable)
 *        21 (0x00200000): - AUTOIBRS (Automatic IBRS Enable)
 *      msr:ia32_sysenter_CS(0x174) = 0x10
 *      msr:ia32_sysenter_ESP(0x175) = 0xfffffe0000035200
 *      msr:ia32_sysenter_EIP(0x176) = 0xffffffffa8801600 (entry_SYSENTER_compat+0x0/0x91)
 *      msr:star(0xc0000081) = user32 CS 0x23, kernel CS 0x10, EIP 0x0
 *      msr:lstar(0xc0000082) = 0xffffffffa8800010 (entry_SYSCALL_64+0x0/0x38)
 *      msr:cstar(0xc0000083) = 0xffffffffa88016a0 (entry_SYSCALL_compat+0x0/0x2c)
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
	show_efer_bit(msr, TCE, "Translation Cache Extension");
	show_efer_bit(msr, MCOMMIT, "MCOMMIT instruction Enable");
	show_efer_bit(msr, INTWB, "Interrupt WBINVD/WBNOINVD Enable");
	show_efer_bit(msr, UAIE, "Upper Address Ignore Enable");
	show_efer_bit(msr, AUTOIBRS, "Automatic IBRS Enable");

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
 *        On current cpu: 0xfffffe0000034000 limit 127
 *        CPU 0: 0xfffffe0000001000 (16 entries)
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
 *           8: <6f 20 00 30 00 8b 00 00>
 *              base 0x00003000, limit 0x206f, flags 0x008b (TSS, Task State Segment)
 *              type=0xb (C-RA), s=0, dpl=0, p=1, avl=0, l=0, d=0, g=0
 *           9: <00 fe ff ff 00 00 00 00>
 *              base 0x0000ffff, limit 0xfe00, flags 0x0000 (TSS+1)
 *              type=0x0 (D---), s=0, dpl=0, p=0, avl=0, l=0, d=0, g=0
 *          15: <00 00 00 00 00 f5 40 00>
 *              base 0x00000000, limit 0x0, flags 0x40f5
 *              type=0x5 (Dv-A), s=1, dpl=3, p=1, avl=0, l=0, d=1, g=0
 *      IDT: 0xfffffe0000000000 limit 4095 (Interrupt Descriptor Table, 256 entries)
 *       0x00: seg 0x10 offset 00000000df0f30b2 Divide by Zero
 *             Sym: divide_error
 *       0x01: seg 0x10 offset 00000000c4f7bc63 Debug
 *             ist=3 (debug stack)
 *             Sym: debug
 *       0x02: seg 0x10 offset 00000000c83148ba Non-maskable Interrupt
 *             ist=2 (non-maskable interrupt stack)
 *             Sym: nmi
 *       0x03: seg 0x10 offset 000000005820aabb Break Point
 *             dpl=3
 *             Sym: int3
 *       0x04: seg 0x10 offset 00000000dad293bf Overflow
 *             dpl=3
 *             Sym: overflow
 *       0x05: seg 0x10 offset 000000000bf6df2a Bound Range Exceeded
 *             Sym: bounds
 *       0x06: seg 0x10 offset 000000002278eaa7 Invalid Opcode
 *             Sym: invalid_op
 *       0x07: seg 0x10 offset 00000000d21b7400 Device Not Available
 *             Sym: device_not_available
 *       0x08: seg 0x10 offset 00000000f5483aff Double Fault
 *             ist=1 (double fault stack)
 *             Sym: double_fault
 *       0x09: seg 0x10 offset 00000000bc2dc92b Coprocessor Segment Overrun
 *             Sym: coprocessor_segment_overrun
 *       0x0a: seg 0x10 offset 00000000c69b907d Invalid TSS
 *             Sym: invalid_TSS
 *       0x0b: seg 0x10 offset 00000000e4e40324 Segment Not Present
 *             Sym: segment_not_present
 *       0x0c: seg 0x10 offset 000000000c161564 Stack Segment Fault
 *             Sym: stack_segment
 *       0x0d: seg 0x10 offset 00000000aa1a1821 General Protection Fault
 *             Sym: general_protection
 *       0x0e: seg 0x10 offset 000000001f31edf6 Page Fault
 *             Sym: async_page_fault
 *       0x0f: seg 0x10 offset 00000000122e9a5d Spurious Interrupt
 *             Sym: spurious_interrupt_bug
 *       0x10: seg 0x10 offset 00000000a6b693eb x87 Floating-Point Exception
 *             Sym: coprocessor_error
 *       0x11: seg 0x10 offset 000000002b5907a8 Alignment Check
 *             Sym: alignment_check
 *       0x12: seg 0x10 offset 00000000598ed431 Machine Check
 *             ist=4 (machine check stack)
 *             Sym: machine_check
 *       0x13: seg 0x10 offset 00000000b644c4c7 SIMD Floating-Point Exception
 *             Sym: simd_coprocessor_error
 *       0x20: seg 0x10 offset 00000000a10ea92b IRET Exception
 *             Sym: irq_move_cleanup_interrupt
 *       0x80: seg 0x10 offset 0000000058da5253 Syscall Vector
 *             dpl=3
 *             Sym: entry_INT80_compat
 *       0xec: seg 0x10 offset 00000000672bfb39 Local Timer Vector
 *             Sym: apic_timer_interrupt
 *       0xf2: seg 0x10 offset 00000000590541c3 Postr Intr Vector
 *             Sym: kvm_posted_intr_ipi
 *       0xf3: seg 0x10 offset 000000005c27f9d5 Hypervisor Callback Vector
 *             Sym: spurious_entries_start+0x38/0xa0
 *       0xf5: seg 0x10 offset 00000000fb1a466e UV Bau Message
 *             Sym: spurious_entries_start+0x48/0xa0
 *       0xf6: seg 0x10 offset 00000000abe33838 IRQ Work Vector
 *             Sym: irq_work_interrupt
 *       0xf7: seg 0x10 offset 000000005042e1f6 x86 Plateform IPI Vector
 *             Sym: x86_platform_ipi
 *       0xf8: seg 0x10 offset 0000000094f39aa7 Reboot Vector
 *             Sym: reboot_interrupt
 *       0xf9: seg 0x10 offset 00000000a8203282 Threshold APIC Vector
 *             Sym: threshold_interrupt
 *       0xfa: seg 0x10 offset 00000000ca9a5efa Thermal APIC Vector
 *             Sym: thermal_interrupt
 *       0xfb: seg 0x10 offset 00000000c132153e Call Function Single Vector
 *             Sym: call_function_single_interrupt
 *       0xfc: seg 0x10 offset 00000000d28d5dca Call Function Vector
 *             Sym: call_function_interrupt
 *       0xfd: seg 0x10 offset 0000000044618b4f Reschedule Vector
 *             Sym: reschedule_interrupt
 *       0xfe: seg 0x10 offset 00000000b72e3e1c Error APIC Vector
 *             Sym: error_interrupt
 *       0xff: seg 0x10 offset 00000000744dd41e Spurious APIC Vector
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

		cpu = raw_smp_processor_id();
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
			/* Removed by commit f1b7d45d3f8f ("x86/irq: Remove unused vectors defines") */
			else if (i == UV_BAU_MESSAGE)
				comment = "UV Bau Message";
#endif
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
				/* Commit 8f34c5b5afce ("x86/exceptions: Make
				 * IST index zero based") changed the names of
				 * the stacks.
				 */
				if (idt_ist == IST_INDEX_DF + 1)
					stack_str = " (double fault stack)";
				else if (idt_ist == IST_INDEX_NMI + 1)
					stack_str = " (non-maskable interrupt stack)";
				else if (idt_ist == IST_INDEX_DB + 1)
					stack_str = " (debug stack)";
				else if (idt_ist == IST_INDEX_MCE + 1)
					stack_str = " (machine check stack)";
#else
				if (idt_ist == DOUBLEFAULT_STACK)
					stack_str = " (double fault stack)";
				else if (idt_ist == NMI_STACK)
					stack_str = " (non-maskable interrupt stack)";
				else if (idt_ist == DEBUG_STACK)
					stack_str = " (debug stack)";
				else if (idt_ist == MCE_STACK)
					stack_str = " (machine check stack)";
#ifdef STACKFAULT_STACK
				/* Commit 6f442be2fb22 ("x86_64, traps: Stop
				 * using IST for #SS") removed STACKFAULT_STACK
				 * in Linux 3.18 and many other stable kernels
				 */
				else if (idt_ist == STACKFAULT_STACK)
					stack_str = " (stack fault stack)";
#endif
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
	pr_info("Current CPU: %u\n", raw_smp_processor_id());
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
