// SPDX-License-Identifier: GPL-2.0
/**
 * Print the value of ARM-specific CPU registers and tables:
 * * some system control coprocessor registers (CR),
 * * the vector table, with decoding of the branch target addresses
 *
 * Documentation:
 * * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0290g/Babebdcb.html
 *   System control coprocessor reference data - Instruction summary
 * * http://www.phrack.org/issues/68/6.html
 *   Android platform based linux kernel rootkit (April 04th 2011)
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>

#include <asm/cputype.h>
#include <asm/cp15.h>

/* Commit 59530adc3f1b ("ARM: Define CPU part numbers and implementors")
 * introduced ARM_CPU_IMP_* macros in 3.9
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
# define ARM_CPU_IMP_ARM 0x41
# define ARM_CPU_IMP_INTEL 0x69
#endif

/* Commit aca7e5920c8e ("ARM: mpu: add PMSA related registers and bitfields to
 * existing headers") instroduced CR_HA and CR_BR in 3.11
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
# ifdef CONFIG_MMU
#  define CR_HA (1 << 17)
# else
#  define CR_BR (1 << 17)
# endif
#endif

/* Commit bbc8d77db655 ("ARM: introduce common set_auxcr/get_auxcr functions")
 * introduced get_auxcr in 3.11
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
static inline unsigned int get_auxcr(void)
{
	unsigned int val;

	asm("mrc p15, 0, %0, c1, c0, 1" : "=r" (val));
	return val;
}
#endif

/**
 * Output example on "qemu-system-arm -cpu arm1176 -machine versatilepb":
 *      CPU ID = 0x410fb767
 *        31..24: Implementer 0x41 (ARM)
 *        23..20: Variant 0x0
 *        19..16: Architecture 15
 *        15.. 4: Part 0xb76
 *         3.. 0: Revision 7
 *        This is ARM1176
 *      Processor Feature Register 0 = 0x00000111
 *      Processor Feature Register 1 = 0x00000011
 *      Debug Feature Register 0 = 0x00000033
 *      Auxiliary Feature Register 0 = 0x00000000
 *      Memory Model Feature Register 0 = 0x01130003
 *      Memory Model Feature Register 1 = 0x10030302
 *      Memory Model Feature Register 2 = 0x01222100
 *      Memory Model Feature Register 3 = 0x00000000
 *      Instruction Set Attributes 0 = 0x00140011
 *      Instruction Set Attributes 1 = 0x12002111
 *      Instruction Set Attributes 2 = 0x11231121
 *      Instruction Set Attributes 3 = 0x01102131
 *      Instruction Set Attributes 4 = 0x00001141
 *      Instruction Set Attributes 5 = 0x00000000
 *
 * and on a BeagleBone Black:
 *      CPU ID = 0x413fc082
 *        31..24: Implementer 0x41 (ARM)
 *        23..20: Variant 0x3
 *        19..16: Architecture 15
 *        15.. 4: Part 0xc08
 *         3.. 0: Revision 2
 *        This is Cortex-A8
 *      Processor Feature Register 0 = 0x00001131
 *      Processor Feature Register 1 = 0x00000011
 *      Debug Feature Register 0 = 0x00010400
 *      Auxiliary Feature Register 0 = 0x00000000
 *      Memory Model Feature Register 0 = 0x01100003
 *      Memory Model Feature Register 1 = 0x20000000
 *      Memory Model Feature Register 2 = 0x01202000
 *      Memory Model Feature Register 3 = 0x00000211
 *      Instruction Set Attributes 0 = 0x00101111
 *      Instruction Set Attributes 1 = 0x13112111
 *      Instruction Set Attributes 2 = 0x21232031
 *      Instruction Set Attributes 3 = 0x11112131
 *      Instruction Set Attributes 4 = 0x00011142
 *      Instruction Set Attributes 5 = 0x00000000
 */
static void dump_arm_cp15_c0(void)
{
#ifdef CONFIG_CPU_CP15
	unsigned int cpu_id, ext_reg;
	const char *cpu_impl = "";
	size_t i;

	/* List from ARM_CPU_PART_* macros in arch/arm/include/asm/cputype.h */
	const struct cpu_part_name {
		unsigned int id;
		const char *name;
	} known_cpu_parts[] = {
		{ 0x4100b020, "ARM11MP-CORE" },
		{ 0x4100b360, "ARM1136" },
		{ 0x4100b560, "ARM1156" },
		{ 0x4100b760, "ARM1176" },
		{ 0x4100c050, "Cortex-A5" },
		{ 0x4100c070, "Cortex-A7" },
		{ 0x4100c080, "Cortex-A8" },
		{ 0x4100c090, "Cortex-A9" },
		{ 0x4100c0d0, "Cortex-A12" },
		{ 0x4100c0e0, "Cortex-A17" },
		{ 0x4100c0f0, "Cortex-A15" }
	};

	/* c0, Main ID Register, accessible via /proc/cpuinfo
	 * mrc p15, 0, %[cpu_id], c0, c0, 0
	 * http://infocenter.arm.com/help/topic/com.arm.doc.dai0099c/DAI0099C_core_type_rev_id.pdf
	 */
	cpu_id = read_cpuid_id();
	if (((cpu_id >> 24) & 0xff) == ARM_CPU_IMP_ARM) /* 0x41, 'A' */
		cpu_impl = " (ARM)";
	else if (((cpu_id >> 24) & 0xff) == ARM_CPU_IMP_INTEL) /* 0x69, 'i' */
		cpu_impl = " (Intel)";
	pr_info("CPU ID = 0x%08x\n", cpu_id);
	pr_info("  31..24: Implementer 0x%x%s\n", (cpu_id >> 24) & 0xff, cpu_impl);
	pr_info("  23..20: Variant 0x%x\n", (cpu_id >> 20) & 0xf);
	pr_info("  19..16: Architecture %u\n", (cpu_id >> 16) & 0xf);
	pr_info("  15.. 4: Part 0x%x\n", (cpu_id >> 4) & 0xfff);
	pr_info("   3.. 0: Revision %u\n", cpu_id & 0xf);

	for (i = 0; i < ARRAY_SIZE(known_cpu_parts); i++) {
		if ((cpu_id & 0xff00fff0) == known_cpu_parts[i].id)
			pr_info("  This is %s\n", known_cpu_parts[i].name);
	}

	/* c0, Extention Registers */
	/* mrc p15, 0, %[ext_reg], c0, c1, 0..1 */
	ext_reg = read_cpuid_ext(CPUID_EXT_PFR0);
	pr_info("Processor Feature Register 0 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_PFR1);
	pr_info("Processor Feature Register 1 = 0x%08x\n", ext_reg);

	/* mrc p15, 0, %[cpu_pfr], c0, c1, 2 */
	ext_reg = read_cpuid_ext(CPUID_EXT_DFR0);
	pr_info("Debug Feature Register 0 = 0x%08x\n", ext_reg);

	/* mrc p15, 0, %[cpu_pfr], c0, c1, 3 */
	ext_reg = read_cpuid_ext(CPUID_EXT_AFR0);
	pr_info("Auxiliary Feature Register 0 = 0x%08x\n", ext_reg);

	/* mrc p15, 0, %[cpu_pfr], c0, c1, 4..7 */
	ext_reg = read_cpuid_ext(CPUID_EXT_MMFR0);
	pr_info("Memory Model Feature Register 0 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_MMFR1);
	pr_info("Memory Model Feature Register 1 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_MMFR2);
	pr_info("Memory Model Feature Register 2 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_MMFR3);
	pr_info("Memory Model Feature Register 3 = 0x%08x\n", ext_reg);

	/* mrc p15, 0, %[cpu_pfr], c0, c2, 0..5 */
	ext_reg = read_cpuid_ext(CPUID_EXT_ISAR0);
	pr_info("Instruction Set Attributes 0 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_ISAR1);
	pr_info("Instruction Set Attributes 1 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_ISAR2);
	pr_info("Instruction Set Attributes 2 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_ISAR3);
	pr_info("Instruction Set Attributes 3 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_ISAR4);
	pr_info("Instruction Set Attributes 4 = 0x%08x\n", ext_reg);
	ext_reg = read_cpuid_ext(CPUID_EXT_ISAR5);
	pr_info("Instruction Set Attributes 5 = 0x%08x\n", ext_reg);
#endif
}

#define show_cr_bit(cr, bitname, desc) \
	pr_info(" %2d (0x%08x): %c %3s (%s)\n", \
		ilog2(CR_##bitname), CR_##bitname, \
		((cr) & CR_##bitname) ? '+' : '-', #bitname, (desc))

/**
 * Output example on "qemu-system-arm -cpu arm1176 -machine versatilepb":
 *      CR = 0x00c5387d (Control Register)
 *        0 (0x00000001): +   M (enable MPU)
 *        1 (0x00000002): -   A (enable strict alignment of data)
 *        2 (0x00000004): +   C (enable level one data cache)
 *        3 (0x00000008): +   W (enable write buffer)
 *        4 (0x00000010): +   P (32-bit exception handler)
 *        5 (0x00000020): +   D (32-bit data address range)
 *        6 (0x00000040): +   L (?)
 *        7 (0x00000080): -   B (Big endian)
 *        8 (0x00000100): -   S (System MMU protection)
 *        9 (0x00000200): -   R (ROM MMU protection)
 *       10 (0x00000400): -   F (?)
 *       11 (0x00000800): +   Z (enable branch prediction)
 *       12 (0x00001000): +   I (enable level one instruction cache)
 *       13 (0x00002000): +   V (exception vectors located at 0xffff0000 instead of 0)
 *       14 (0x00004000): -  RR (round-robin replacement strategy for the cache)
 *       15 (0x00008000): -  L4 (loads to pc do not set the T bit)
 *       16 (0x00010000): +  DT (global enable for data TCM)
 *       17 (0x00020000): -  HA (hardware management of Access Flag)
 *       18 (0x00040000): +  IT (global enable for instruction TCM)
 *       19 (0x00080000): -  ST (?)
 *       21 (0x00200000): -  FI (enable low interrupt latency configuration)
 *       22 (0x00400000): +   U (enable unaligned data access operations)
 *       23 (0x00800000): +  XP (enable extended page tables)
 *       24 (0x01000000): -  VE (enable the VIC interface to determine interrupt vectors)
 *       25 (0x02000000): -  EE (value of CPSR E bit on an exception)
 *       28 (0x10000000): - TRE (enable TEX remap)
 *       29 (0x20000000): - AFE (enable Force AP functionality in the MMU)
 *       30 (0x40000000): -  TE (enable thumb exception)
 *      Aux CR = 0x00000007
 *      Copro Access = 0xc0f00000
 *        cp0: denied
 *        cp1: denied
 *        cp2: denied
 *        cp3: denied
 *        cp4: denied
 *        cp5: denied
 *        cp6: denied
 *        cp7: denied
 *        cp8: denied
 *        cp9: denied
 *        cp10 (VFP): full
 *        cp11 (VFP): full
 *        cp12: denied
 *        cp13: denied
 *        cp14: denied
 *        cp15 (system control): full
 *
 * On a BeagleBone Black, CR = 0x50c5387d, Aux CR = 0x00000042,
 * Copro Access = 0x00f00000.
 */
static void dump_arm_cp15_c1(void)
{
#ifdef CONFIG_CPU_CP15
	unsigned long cr;
	unsigned int aux_cr, copro_access, i;
	const char *const cpa_descriptions[4] = {
		"denied", "privileged", "?", "full"
	};
	const char *cp_desc, *access_desc;

	/* c1, Control Register
	 * mrc p15, 0, %[cr], c1, c0, 0
	 */
	cr = get_cr();
	pr_info("CR = 0x%08lx (Control Register)\n", cr);
	show_cr_bit(cr, M, "enable MPU");
	show_cr_bit(cr, A, "enable strict alignment of data");
	show_cr_bit(cr, C, "enable level one data cache");
	show_cr_bit(cr, W, "enable write buffer");
	show_cr_bit(cr, P, "32-bit exception handler");
	show_cr_bit(cr, D, "32-bit data address range");
	show_cr_bit(cr, L, "?"); /* implementation defined */
	show_cr_bit(cr, B, "Big endian");
	show_cr_bit(cr, S, "System MMU protection");
	show_cr_bit(cr, R, "ROM MMU protection");
	show_cr_bit(cr, F, "?"); /* implementation defined */
	show_cr_bit(cr, Z, "enable branch prediction");
	show_cr_bit(cr, I, "enable level one instruction cache");
	show_cr_bit(cr, V, "exception vectors located at 0xffff0000 instead of 0");
	show_cr_bit(cr, RR, "round-robin replacement strategy for the cache");
	show_cr_bit(cr, L4, "loads to pc do not set the T bit");
	show_cr_bit(cr, DT, "global enable for data TCM");
#ifdef CONFIG_MMU
	show_cr_bit(cr, HA, "hardware management of Access Flag");
#else
	show_cr_bit(cr, BR, "MPU Background region enable (PMSA)");
#endif
	show_cr_bit(cr, IT, "global enable for instruction TCM");
	show_cr_bit(cr, ST, "?"); /* implementation defined */
	show_cr_bit(cr, FI, "enable low interrupt latency configuration");
	show_cr_bit(cr, U, "enable unaligned data access operations");
	show_cr_bit(cr, XP, "enable extended page tables");
	show_cr_bit(cr, VE, "enable the VIC interface to determine interrupt vectors");
	show_cr_bit(cr, EE, "value of CPSR E bit on an exception");
	show_cr_bit(cr, TRE, "enable TEX remap");
	show_cr_bit(cr, AFE, "enable Force AP functionality in the MMU");
	show_cr_bit(cr, TE, "enable thumb exception");

	/* c1, Auxiliary Control Register
	 * mrc p15, 0, %[aux_cr], c1, c0, 1
	 */
	aux_cr = get_auxcr();
	pr_info("Aux CR = 0x%08x\n", aux_cr);

	/* c1, Coprocessor Access Control Register
	 * mrc p15, 0, %[copro_access], c1, c0, 2
	 */
	copro_access = get_copro_access();
	pr_info("Copro Access = 0x%08x\n", copro_access);
	for (i = 0; i <= 15; i++) {
		cp_desc = "";
		if (i == 10 || i == 11)
			cp_desc = " (VFP)";
		else if (i == 15)
			cp_desc = " (system control)";
		access_desc = cpa_descriptions[(copro_access >> (2 * i)) & 3];
		pr_info("  cp%u%s: %s\n", i, cp_desc, access_desc);
	}
#endif
}

/**
 * Show an instruction in the vector table
 * Linux implementation in arch/arm/kernel/entry-armv.S
 */
static void show_vector_instruction(unsigned long addr)
{
	unsigned long ldpc_from = 0;
	unsigned long br_addr = 0;

	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		uint16_t instr1 = *(uint16_t *)addr;
		uint16_t instr2 = *(uint16_t *)(addr + 2);

		/* Decode Thumb instruction */
		if ((instr1 & 0xff00) == 0xdf00 && instr2 == 0xbf00) {
			/* svc 0 ; nop */
			pr_info("  ... svc %u\n", (unsigned int)(instr1 & 0xff));
		} else if (instr1 == 0xf000 && (instr2 & 0xf800) == 0xb800) {
			/* Branch instruction */
			br_addr = addr + 4 + ((instr2 & 0x7ff) << 1);
		} else if (instr1 == 0xf8df && (instr2 & 0xf000) == 0xf000) {
			/* ldr pc, [pc+offset] */
			ldpc_from = addr + 4 + (instr2 & 0xfff);
		}
	} else {
		uint32_t instr = *(uint32_t *)addr;

		/* Decode ARM instruction */
		if ((instr & 0xff000000UL) == 0xea000000UL) {
			/* Branch instruction */
			br_addr = addr + 8;
			if (instr & 0x800000)
				br_addr -= (0x1000000 - (instr & 0xffffff)) * 4;
			else
				br_addr += (instr & 0xffffff) * 4;
		} else if ((instr & 0xfffff000UL) == 0xe59ff000UL) {
			/* ldr pc, [pc+offset] */
			ldpc_from = addr + 8 + (instr & 0xfff);
		}
	}

	if (ldpc_from && ldpc_from >= CONFIG_VECTORS_BASE &&
	    ldpc_from < CONFIG_VECTORS_BASE + 2 * PAGE_SIZE) {
		pr_info("  ... load pc from %p\n", (void *)ldpc_from);
		br_addr = *(unsigned long *)ldpc_from;
	}
	if (br_addr) {
		if (br_addr < CONFIG_VECTORS_BASE) {
			pr_info("  ... branch to %p (%pS)", (void *)br_addr,
				(void *)br_addr);
		} else
			pr_info("  ... branch to %p\n", (void *)br_addr);
	}
}

/**
 * Output example on "qemu-system-arm -cpu arm1176 -machine versatilepb"
 * (Linux 3.18):
 *      Exception vectors table at ffff0000. Instructions (ARM):
 *        0x00: 0xea0003ff (reset)
 *        ... branch to ffff1004
 *        0x04: 0xea000465 (undefined instruction)
 *        ... branch to ffff11a0
 *        0x08: 0xe59ffff0 (software interrupt)
 *        ... load pc from ffff1000
 *        ... branch to c0014be0 (vector_swi+0x0/0x6c)
 *        0x0c: 0xea000443 (prefetch abort)
 *        ... branch to ffff1120
 *        0x10: 0xea000422 (data abort)
 *        ... branch to ffff10a0
 *        0x14: 0xea000481 (address exception handler)
 *        ... branch to ffff1220
 *        0x18: 0xea000400 (IRQ, Interrupt Request)
 *        ... branch to ffff1020
 *        0x1c: 0xea000487 (FIQ, Fast Interrupt Request)
 *        ... branch to ffff1240
 *
 * Output example on a BeagleBone Black (Linux 3.8.13):
 *      Exception vectors table at ffff0000. Instructions (Thumb):
 *        0x00: 0xbf00df00 (reset)
 *        ... svc 0
 *        0x04: 0xb9bcf000 (undefined instruction)
 *        ... branch to ffff0380
 *        0x08: 0xf414f8df (software interrupt)
 *        ... load pc from ffff0420
 *        ... branch to c000c8a1 (vector_swi+0x1/0x4e)
 *        0x0c: 0xb978f000 (prefetch abort)
 *        ... branch to ffff0300
 *        0x10: 0xb936f000 (data abort)
 *        ... branch to ffff0280
 *        0x14: 0xb9f6f000 (address exception handler)
 *        ... branch to ffff0404
 *        0x18: 0xb8f2f000 (IRQ, Interrupt Request)
 *        ... branch to ffff0200
 *        0x1c: 0xb9f0f000 (FIQ, Fast Interrupt Request)
 *        ... branch to ffff0400
 */
static void dump_arm_vectors(void)
{
	unsigned long vectors_base, instr;
	unsigned long addr;
	size_t i;

	const struct vector_entry_desc {
		unsigned int offset;
		const char *name;
	} vector_entries[] = {
		{ 0x00, "reset" },
		{ 0x04, "undefined instruction" },
		{ 0x08, "software interrupt" },
		{ 0x0c, "prefetch abort" },
		{ 0x10, "data abort" },
		{ 0x14, "address exception handler" },
		{ 0x18, "IRQ, Interrupt Request" },
		{ 0x1c, "FIQ, Fast Interrupt Request" }
	}, *entry;

	/* Usually the vector base is 0xffff0000 (if vectors_high()) or 0 */
	vectors_base = UL(CONFIG_VECTORS_BASE);
	pr_info("Exception vectors table at %08lx. Instructions (%s):\n",
		vectors_base,
		IS_ENABLED(CONFIG_THUMB2_KERNEL) ? "Thumb" : "ARM");

	if (vectors_high() && vectors_base != 0xffff0000UL) {
		pr_warn("... it is not high even though bit V is set in CR. Skip dump\n");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(vector_entries); i++) {
		entry = &vector_entries[i];
		addr = vectors_base + entry->offset;
		instr = *(unsigned long *)addr;
		pr_info("  0x%02x: 0x%lx (%s)\n", entry->offset, instr,
			entry->name);
		show_vector_instruction(addr);
	}
}

static int __init cpu_arm_init(void)
{
	pr_info("Current CPU: %u\n", smp_processor_id());
	dump_arm_cp15_c0();
	dump_arm_cp15_c1();
	dump_arm_vectors();
	return 0;
}

static void __exit cpu_arm_exit(void)
{
}

module_init(cpu_arm_init);
module_exit(cpu_arm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Iooss");
MODULE_DESCRIPTION("Print the value of ARM-specific CPU registers and tables");
