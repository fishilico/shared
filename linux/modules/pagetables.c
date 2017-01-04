/**
 * Show the kernel page table, with some information about how an address to
 * paged memory is resolved.
 *
 * Code inspired from x86 dump page implementation:
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/mm/dump_pagetables.c
 *
 * Documentation:
 * * ARM:
 *   - https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/arm/mm/dump.c
 *     Debug helper to dump the current kernel pagetables of the system.
 *   - https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/arm/include/asm/pgtable-3level.h
 *     Page bits for 3-level page tables
 *   - https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/arm/mm/mmu.c
 *     struct mem_type mem_types[] definition
 *   - https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm/memory.txt
 *     Memory structure
 *
 * * x86:
 *   - https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/mm/dump_pagetables.c
 *     Debug helper to dump the current kernel pagetables of the system.
 *   - https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/pgtable_types.h
 *     Page bits
 *   - https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/x86/x86_64/mm.txt
 *     Memory structure
 *
 * In qemu monitor console, "info tlb" show the page table ("virtual to physical memory mappings").
 *
 * Pax Team also implemented a user-space dumper of pagetables, available at:
 *   https://grsecurity.net/~paxguy1/kmaps.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/version.h>

#include <asm/fixmap.h>
#include <asm/pgtable.h>

/* Merge large pagetables together on x86 */
#define PAGETABLES_MERGE_LARGE 1

/* Define some macros which prevents some #ifdef */
#ifdef CONFIG_ARM
# define pud_large(pgd) false
# define pgd_large(pgd) false

/* pmd_large has been introduced in ARM in Linux 3.14 by commit 1fd15b879d00
 * ("ARM: add support to dump the kernel page tables")
 */
# if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#  ifdef CONFIG_ARM_LPAE
/* arch/arm/include/asm/pgtable-3level.h */
#   define pmd_large(pmd) pmd_sect(pmd)
#  else
/* arch/arm/include/asm/pgtable-2level.h */
#   define pmd_large(pmd) (pmd_val(pmd) & 2)
#  endif
# endif
#endif

struct pg_state {
	struct seq_file *seq;
	const struct addr_marker *marker;
	unsigned long start_address;
	unsigned int level;
	u64 current_prot;
	unsigned long lines;
};

struct addr_marker {
	unsigned long address;
	const char *name;
	unsigned long max_lines;
};


/**
 * Describe the current protection flags in the pg_state structure
 */
static void print_prot(struct pg_state *st)
{
	u64 pr = st->current_prot;
	unsigned int level = st->level;

#ifdef CONFIG_ARM
	if (level == 4) {
		/* PTE flags */
		seq_puts(st->seq, (pr & L_PTE_RDONLY) ? "RO" : "rw");
		seq_puts(st->seq, (pr & L_PTE_XN) ? "NX" : "-x");
		if (pr & L_PTE_USER)
			seq_puts(st->seq, ", USR");
		if (pr & L_PTE_SHARED)
			seq_puts(st->seq, ", SHD");
		if (!(pr & L_PTE_PRESENT) && (pr & L_PTE_FILE))
			seq_puts(st->seq, ", FILE");
		if ((pr & L_PTE_MT_MASK) == L_PTE_MT_UNCACHED)
			seq_puts(st->seq, ", SO/UNCACHED");
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_BUFFERABLE)
			seq_puts(st->seq, ", MEM/BUFFERABLE/WC");
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_WRITETHROUGH)
			seq_puts(st->seq, ", MEM/CACHED/WT");
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_WRITEBACK)
			seq_puts(st->seq, ", MEM/CACHED/WBRA");
# ifndef CONFIG_ARM_LPAE
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_MINICACHE)
			seq_puts(st->seq, ", MEM/MINICACHE");
# endif
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_WRITEALLOC)
			seq_puts(st->seq, ", MEM/CACHED/WBWA");
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_DEV_SHARED)
			seq_puts(st->seq, ", DEV/SHARED");
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_DEV_NONSHARED)
			seq_puts(st->seq, ", DEV/NONSHARED");
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_DEV_WC)
			seq_puts(st->seq, ", DEV/WC");
		else if ((pr & L_PTE_MT_MASK) == L_PTE_MT_DEV_CACHED)
			seq_puts(st->seq, ", DEV/CACHED");

		pr &= ~(
			L_PTE_PRESENT |		/* 0, present */
			L_PTE_YOUNG |		/* 1 */
			L_PTE_FILE |		/* 2, file, if !present */
			L_PTE_MT_MASK |		/* 2-5 */
			L_PTE_DIRTY |		/* 6 */
			L_PTE_RDONLY |		/* 7, read only */
			L_PTE_USER |		/* 8 */
			L_PTE_XN |		/* 9, execute never */
			L_PTE_SHARED |		/* 10 */
			L_PTE_NONE);		/* 11 */
	} else if (level == 3) {
		/* PMD flags, also known as section flags */
# ifdef CONFIG_ARM_LPAE
		seq_puts(st->seq, (pr & L_PMD_SECT_RDONLY) ? "RO" : "rw");
		seq_puts(st->seq, (pr & PMD_SECT_XN) ? "NX" : "-x");
		if (pr & PMD_SECT_USER)
			seq_puts(st->seq, ", USR");
# elif __LINUX_ARM_ARCH__ >= 6
		switch (pr & (PMD_SECT_APX | PMD_SECT_AP_WRITE)) {
		case PMD_SECT_APX | PMD_SECT_AP_WRITE: /* Kernel RO */
		case 0: /* User RO */
			seq_puts(st->seq, "RO");
			break;
		case PMD_SECT_AP_WRITE: /* Kernel RW or User RW */
			seq_puts(st->seq, "RW");
			break;
		default:
			seq_puts(st->seq, "?APX?");
		}
		seq_puts(st->seq, (pr & PMD_SECT_XN) ? "NX" : "-x");
		if (pr & PMD_SECT_AP_READ)
			seq_puts(st->seq, ", USR");
# else /* ARMv4/ARMv5, untested */
		seq_puts(st->seq, (pr & PMD_SECT_AP_WRITE) ? "RW" : "ro");
		seq_puts(st->seq, (pr & PMD_SECT_XN) ? "NX" : "-x");
		if (pr & PMD_SECT_AP_READ)
			seq_puts(st->seq, ", USR");
# endif
		if (pr & PMD_SECT_S)
			seq_puts(st->seq, ", SHD");
		if ((pr & PMD_TYPE_MASK) == PMD_TYPE_FAULT)
			seq_puts(st->seq, ", FLT");
		if ((pr & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
			seq_puts(st->seq, ", TBL");

		if ((pr & PMD_DOMAIN(3)) == PMD_DOMAIN(DOMAIN_IO)) {
			if ((pr & PMD_SECT_S) == PMD_SECT_S)
				seq_puts(st->seq, ", DEV/SHARED");
			else if ((pr & PMD_SECT_WB) == PMD_SECT_WB)
				seq_puts(st->seq, ", DEV/CACHED");
			else
				seq_printf(st->seq, ", DEVICE?? %Lx %x %x",
					   pr & (PMD_SECT_S | PMD_SECT_WB),
					   PMD_SECT_S, PMD_SECT_WB);
			pr &= ~(PMD_DOMAIN(DOMAIN_IO)|PMD_SECT_S|PMD_SECT_WB);
		}

		pr &= ~(
			PMD_TYPE_MASK |
			PMD_SECT_BUFFERABLE |
			PMD_SECT_CACHEABLE |
			PMD_SECT_AP_WRITE |
			PMD_SECT_AP_READ |
			PMD_SECT_XN |
			PMD_SECT_APX |
# ifdef CONFIG_ARM_LPAE
			PMD_SECT_USER |
			L_PMD_SECT_VALID |
			L_PMD_SECT_DIRTY |
			L_PMD_SECT_SPLITTING |
			L_PMD_SECT_NONE |
			L_PMD_SECT_RDONLY |
# endif
			0);
	}
#elif defined(CONFIG_X86)
	seq_puts(st->seq, (pr & _PAGE_RW) ? "RW" : "ro");
	seq_puts(st->seq, (pr & _PAGE_NX) ? "NX" : "-x");
	if (pr & _PAGE_USER)
		seq_puts(st->seq, ", USR");
	if (pr & _PAGE_PWT)
		seq_puts(st->seq, ", PWT");
	if (pr & _PAGE_PCD)
		seq_puts(st->seq, ", PCD");
	if (!(pr & _PAGE_GLOBAL))
		seq_puts(st->seq, ", not-GLB");

	/* Bit 7 has a different meaning on level 3 vs 4 */
	if (level <= 3 && pr & _PAGE_PSE)
		seq_puts(st->seq, ", PSE");

	if ((level == 4 && pr & _PAGE_PAT) ||
	    ((level == 3 || level == 2) && pr & _PAGE_PAT_LARGE))
		seq_puts(st->seq, ", PAT");

	pr &= ~(
		_PAGE_PRESENT |		/* 0, Present */
		_PAGE_RW |		/* 1, Writeable */
		_PAGE_USER |		/* 2, Userspace addressable */
		_PAGE_PWT |		/* 3, Page Write Through */
		_PAGE_PCD |		/* 4, Page Cache Disabled */
		_PAGE_ACCESSED |	/* 5, was accessed */
		_PAGE_DIRTY |		/* 6, was written to */
		_PAGE_PSE |		/* 7, Page Size Extented 4 MB */
		_PAGE_PAT |	/* on 4KB: 7, Page Table Atttibute Index */
		_PAGE_GLOBAL |		/* 8, Global TLB entry */
		_PAGE_PAT_LARGE |	/* 12, on 2MB or 1GB pages */
		_PAGE_NX);		/* 63, No Execute */
#endif

	if (pr)
		seq_printf(st->seq, ", %#Lx", pr);
}

/**
 * Print additional information about the current address
 */
static void print_additional_desc(struct pg_state *st, unsigned long last_addr)
{
	unsigned long addr = st->start_address;
	char separator = ':';

#ifdef CONFIG_KALLSYMS
	/* Show which module owns the address, if any */
	if (addr >= MODULES_VADDR && addr < MODULES_END) {
		char sym[KSYM_SYMBOL_LEN], *modname;

		snprintf(sym, sizeof(sym), "%ps", (void *)addr);
		modname = strchr(sym, '[');
		if (modname)
			seq_printf(st->seq, " %s", modname);
	}
#endif

#define describe_with_pointer(ptr, desc) \
	do { \
		unsigned long _ptr = (unsigned long)(ptr); \
		if (addr <= _ptr && _ptr < last_addr) { \
			seq_printf(st->seq, "%c %s", separator, desc); \
			separator = ','; \
		} \
	} while (0)

	/* Detect kernel .text through a function pointer.
	 * On x86_32 without KASLR, it is LOAD_OFFSET + LOAD_PHYSICAL_ADDR.
	 * On x86_64 without KASLR, it is __START_KERNEL.
	 */
	describe_with_pointer(snprintf, "kernel .text");

	/* Detect kernel .data through a symbol */
	describe_with_pointer(&init_task, "kernel .data");

	/* Detect kernel .bss through a symbol marked "B" in kallsyms */
	describe_with_pointer(&reset_devices, "kernel .bss");

	/* Show the stack pointer. */
	describe_with_pointer(&addr, "current stack");

#ifdef CONFIG_X86
	/* Show where the percpu area is on x86, using current_task */
	describe_with_pointer(this_cpu_ptr(&current_task), "percpu area");
#endif

#ifdef CONFIG_ARM
	describe_with_pointer(CONFIG_VECTORS_BASE, "vectors");
	describe_with_pointer(CONFIG_VECTORS_BASE + 0x1000, "vectors stubs");
#elif defined(CONFIG_X86_64)
	/* Before commit f40c330091c7, VSYSCALL_ADDR was a function */
# if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
#  undef VSYSCALL_ADDR
#  define VSYSCALL_ADDR VSYSCALL_START
# endif
	describe_with_pointer(VSYSCALL_ADDR, "vsyscall pages (with clock)");
#endif

#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	/* Commit 4eefbe792bae ("x86: Use a read-only IDT alias on all CPUs")
	 * made the IDT mapped read-only at a fixed location
	 */
	describe_with_pointer(fix_to_virt(FIX_RO_IDT), "IDT");
#endif

#undef describe_with_pointer
}

/**
 * Show a new block of pages while walking paging-related tables
 */
static void note_page(struct pg_state *st, unsigned long addr,
		      unsigned int level, u64 prot)
{
	static const char units[] = "KMGTPE";

	if (!st->level) {
		st->level = level;
		st->current_prot = prot;
		st->start_address = addr;
		seq_printf(st->seq, "---[ %s @%#lx ]---\n",
			   st->marker->name, st->marker->address);
	} else if (prot != st->current_prot || addr >= st->marker[1].address ||
		   (!PAGETABLES_MERGE_LARGE && level != st->level)) {
		if (st->current_prot) {
			if (!st->marker->max_lines ||
			    st->lines < st->marker->max_lines) {
				const char *unit = units;
				unsigned long human_size, s;
				unsigned int shift;

				if (addr) {
					seq_printf(st->seq, "%lx-%lx  ",
						   st->start_address, addr);
				} else {
					seq_printf(st->seq, "%lx-%-*s  ",
						   st->start_address,
						   2 * (int)sizeof(long),
						   "end");
				}

				print_prot(st);

				/* Eliminates all least-significant zeros */
				human_size = (addr - st->start_address) >> 10;
				while (!(human_size & 1023) && unit[1]) {
					human_size >>= 10;
					unit++;
				}
				/* Show several parts */
				seq_puts(st->seq, " (");
				for (shift = (fls_long(human_size) - 1) / 10;
				     shift > 0; shift--) {
					s = human_size >> (10 * shift);
					human_size -= s << (10 * shift);
					seq_printf(st->seq, "%lu%c ",
						   s, unit[shift]);
				}
				seq_printf(st->seq, "%lu%c)",
					   human_size, *unit);

				print_additional_desc(st, addr);
				seq_puts(st->seq, "\n");
			} else if (st->lines == st->marker->max_lines) {
				seq_puts(st->seq, "...\n");
			}
			st->lines++;
		}

		while (addr >= st->marker[1].address) {
			st->marker++;
			seq_printf(st->seq, "---[ %s @%#lx ]---\n",
				   st->marker->name, st->marker->address);
			st->lines = 0;
		}

		st->start_address = addr;
		st->current_prot = prot;
		st->level = level;
	}
}

/**
 * Strip the page frame number from PTE, PMD, PUD
 */
static inline u64 pte_val_nopfn(pte_t pte)
{
#ifdef CONFIG_X86
	return pte_val(pte) & PTE_FLAGS_MASK;
#else
	return pte_val(pte) ^ pte_val(pfn_pte(pte_pfn(pte), 0));
#endif
}

static inline u64 pmd_val_nopfn(pmd_t pmd)
{
	u64 val = pmd_val(pmd);
#ifdef CONFIG_X86
	if (PAGETABLES_MERGE_LARGE)
		val &= ~_PAGE_PSE;
	return val & PTE_FLAGS_MASK;
#elif defined(CONFIG_ARM)
	return val ^ (((val & SECTION_MASK & PHYS_MASK) >> PAGE_SHIFT) <<
		      PAGE_SHIFT);
#else
	return val ^ (((val & PMD_MASK & PHYS_MASK) >> PAGE_SHIFT) <<
		      PAGE_SHIFT);
#endif
}

static inline u64 pud_val_nopfn(pud_t pud)
{
#ifdef CONFIG_X86
	u64 val = pud_val(pud) & PTE_FLAGS_MASK;

	if (PAGETABLES_MERGE_LARGE)
		val &= ~_PAGE_PSE;
	return val;
#elif PTRS_PER_PMD == 1
	return pud_val(pud);
#else
	return pud_val(pud) ^ pud_val(pfn_pud(pud_pfn(pud), 0));
#endif
}

static inline u64 pgd_val_nopfn(pgd_t pgd)
{
#ifdef CONFIG_X86
	return pgd_val(pgd) & PTE_FLAGS_MASK;
#else
	return pgd_val(pgd);
#endif
}

/**
 * Walk the level of PTE
 */
static void walk_pte(struct pg_state *st, pte_t *pte, unsigned long addr)
{
	unsigned int i;

	for (i = 0; i < PTRS_PER_PTE; i++, pte++, addr += PAGE_SIZE) {
#if 0
		/* Dump PTE entries */
		unsigned long addr_phys = __pa(addr);

		if (pte_val(*pte) && addr_phys != pte_pfn(*pte) << PAGE_SHIFT) {
			seq_printf(st->seq, "    PTE %3u @ %#lx: %lx vs %lx\n",
				   i, addr, pte_val(*pte), addr_phys);
		}
#endif
		note_page(st, addr, 4, pte_val_nopfn(*pte));
	}
}

/**
 * Walk the level of PMD tables
 */
static void walk_pmd(struct pg_state *st, pmd_t *pmd, unsigned long addr)
{
	unsigned int i;

	for (i = 0; i < PTRS_PER_PMD; i++, pmd++, addr += PMD_SIZE) {
		if (pmd_none(*pmd) || pmd_large(*pmd) || !pmd_present(*pmd))
			note_page(st, addr, 3, pmd_val_nopfn(*pmd));
		else
			walk_pte(st, pte_offset_kernel(pmd, 0), addr);

#ifdef CONFIG_ARM
		/* On ARM with 2-level pages, there are 2 hardware "sections"
		 * (PTE tables) per PGD entry (seen at walk_pmd level).
		 * As the number of PTEs is also doubled, it does not change
		 * anything for usual pages, bug large pages need their
		 * protection flags updated.
		 */
		if (SECTION_SIZE < PMD_SIZE && pmd_large(pmd[1])) {
			note_page(st, addr + SECTION_SIZE, 3,
				  pmd_val_nopfn(pmd[1]));
		}
#endif
	}
}

/**
 * Walk the level of PUD tables
 */
static void walk_pud(struct pg_state *st, pud_t *pud, unsigned long addr)
{
	unsigned int i;

	if (PTRS_PER_PUD == 1) {
		walk_pmd(st, (pmd_t *)pud, addr);
	} else {
		for (i = 0; i < PTRS_PER_PUD; i++, pud++, addr += PUD_SIZE) {
			if (pud_none(*pud) || pud_large(*pud) ||
			    !pud_present(*pud))
				note_page(st, addr, 2, pud_val_nopfn(*pud));
			else
				walk_pmd(st, pmd_offset(pud, 0), addr);
		}
	}
}

/**
 * Walk the level of PGD tables
 */
static void walk_pgd(struct pg_state *st, pgd_t *pgd)
{
	unsigned int i;
	unsigned long addr;

	/* Start with the first level of markers */
	addr = st->marker->address;
	i = pgd_index(addr);
	for (pgd = &pgd[i]; i < PTRS_PER_PGD; i++, pgd++, addr += PGDIR_SIZE) {
		if (pgd_none(*pgd) || pgd_large(*pgd) || !pgd_present(*pgd))
			note_page(st, addr, 1, pgd_val_nopfn(*pgd));
		else
			walk_pud(st, pud_offset(pgd, 0), addr);
	}

	/* Flush out the last page */
	note_page(st, addr, 0, 0);
}

/**
 * Present the components of an address
 *
 * Output example on ARM (qemu-system-arm -cpu arm1176 -machine versatilepb):
 *     Page Global Directory pointers = 2048
 *     Page Upper Directory pointers = 1
 *     Page Middle Directory pointers = 1
 *     Page Table Entry pointers = 512
 *     Page size = 4096
 *     Bits per PGD, PUD, PMD, PTE, page = 11, 0, 0, 9, 12
 *       ... gggg gggg  ggge eeee
 *       ... eeee pppp  pppp pppp
 *
 * Output example on x86_64:
 *     Page Global Directory pointers = 512
 *     Page Upper Directory pointers = 512
 *     Page Middle Directory pointers = 512
 *     Page Table Entry pointers = 512
 *     Page size = 4096
 *     Bits per PGD, PUD, PMD, PTE, page = 9, 9, 9, 9, 12
 *       ... 0000 0000  0000 0000
 *       ... gggg gggg  guuu uuuu
 *       ... uumm mmmm  mmme eeee
 *       ... eeee pppp  pppp pppp
 */
static void show_address_comp(struct seq_file *s)
{
	char address_bit[8 * sizeof(void *)], *p;
	unsigned int pgd_bits, pud_bits, pmd_bits, pte_bits, page_bits, i;

	seq_printf(s, "Page Global Directory pointers = %d\n", PTRS_PER_PGD);
	seq_printf(s, "Page Upper Directory pointers = %d\n", PTRS_PER_PUD);
	seq_printf(s, "Page Middle Directory pointers = %d\n", PTRS_PER_PMD);
	seq_printf(s, "Page Table Entry pointers = %d\n", PTRS_PER_PTE);
	seq_printf(s, "Page size = %lu\n", (unsigned long)PAGE_SIZE);

	pgd_bits = ilog2(PTRS_PER_PGD);
	pud_bits = ilog2(PTRS_PER_PUD);
	pmd_bits = ilog2(PTRS_PER_PMD);
	pte_bits = ilog2(PTRS_PER_PTE);
	page_bits = ilog2(PAGE_SIZE);

	BUILD_BUG_ON(PTRS_PER_PTE * PAGE_SIZE != PMD_SIZE);
	BUILD_BUG_ON(PTRS_PER_PMD * PMD_SIZE != PUD_SIZE);
	BUILD_BUG_ON(PTRS_PER_PUD * PUD_SIZE != PGDIR_SIZE);

	seq_printf(s,
		   "Bits per PGD, PUD, PMD, PTE, page = %u, %u, %u, %u, %u\n",
		   pgd_bits, pud_bits, pmd_bits, pte_bits, page_bits);

	if (pgd_bits + pud_bits + pmd_bits + pte_bits + page_bits >
	    8 * sizeof(void *)) {
		pr_err("Too many bits in page table components\n");
		return;
	}

	/* Show the bits in address */
	p = &address_bit[8 * sizeof(void *) - 1];
	for (i = 0; i < page_bits; i++)
		*(p--) = 'p';
	for (i = 0; i < pte_bits; i++)
		*(p--) = 'e';
	for (i = 0; i < pmd_bits; i++)
		*(p--) = 'm';
	for (i = 0; i < pud_bits; i++)
		*(p--) = 'u';
	for (i = 0; i < pgd_bits; i++)
		*(p--) = 'g';
	while (p >= address_bit)
		*(p--) = '0';
	for (i = 0; i < (unsigned int)(sizeof(void *) / 2); i++) {
		seq_printf(s, "  ... %.4s %.4s  %.4s %.4s\n",
			   &address_bit[16 * i], &address_bit[16 * i + 4],
			   &address_bit[16 * i + 8], &address_bit[16 * i + 12]);
	}
}

/**
 * Get a pointer to the PGD table
 *
 * Output example on ARM:
 *     PGD table at df50c000 (phys 0x9f50c000)
 *       ... cp15,c2,c0,0 = 0x9f50c000
 *
 * Output example on x86_64:
 *     PGD table at ffff8800371df000 (phys 0x371df000)
 *       ... cr3 = 0x371df000
 */
static pgd_t *get_pgd_address(struct seq_file *s)
{
	unsigned int cpu_id;
	pgd_t *pgd_table;
	unsigned long pgd_phys;

	/* Disable preemption while reading current CPU PGD */
	cpu_id = get_cpu();

#if defined(CONFIG_PAX_PER_CPU_PGD) && defined(CONFIG_X86_64)
	/* PAX defines two PGD, one for usermode and one for kernelmode */
	pgd_table = get_cpu_pgd(cpu_id, kernel);
#else
	/* Use current->active_mm because swapper_pg_dir is not exported */
	pgd_table = current->active_mm->pgd;
#endif
	pgd_phys = __pa(pgd_table);
	seq_printf(s, "PGD table (cpu %u) at %pK (phys %#lx)\n",
		   cpu_id, pgd_table, pgd_phys);

#ifdef CONFIG_ARM
	/* On ARM the address of the PGD is in the 14 low bits of the
	 * Translation Table Base Register (TTBR), which is coprocessor
	 * register 15, c2, c0, 0:
	 *     mrc p15, 0, %[pg_value], c2, c0, 0
	 *     pgd = phys_to_virt(pg_value & ~0x3fff);
	 */
	{
		pgd_t *cpu_pgd;
		unsigned long cpu_pgd_phys;

		cpu_pgd = cpu_get_pgd();
		cpu_pgd_phys = virt_to_phys(cpu_pgd);
		seq_printf(s, "  ... cp15,c2,c0,0 = %#lx\n", cpu_pgd_phys);
		if (cpu_pgd_phys != pgd_phys) {
			seq_printf(s,
				"WARN: CPU uses a different PGD: %#lx != %#lx\n",
				cpu_pgd_phys, pgd_phys);
			/* Trust the CPU more than the kernel structures */
			pgd_table = cpu_pgd;
		}
	}
#elif defined(CONFIG_X86)
	/* On x86 the address of the PGD is in cr3 */
	{
		unsigned long cr3_raw, cr3;

		/* Mask high bits and low bits (PCID) of CR3 register */
		cr3_raw = read_cr3();
		cr3 = cr3_raw & __PHYSICAL_MASK & PAGE_MASK;
		if (cr3 == cr3_raw)
			seq_printf(s, "  ... cr3 = %#lx\n", cr3);
		else
			seq_printf(s, "  ... cr3 = %#lx -> masked %lx\n",
				   cr3_raw, cr3);
		if (cr3 != pgd_phys) {
			seq_printf(s,
				"WARN: CR3 does not contains the current PGD address: %#lx != %#lx\n",
				cr3, pgd_phys);
			/* Trust CR3 more than the kernel structures,
			 * because on -grsec kernels the ->mm->pgd tables are
			 * empty
			 */
			pgd_table = (pgd_t *)__va(cr3);
		}
	}
#endif
	put_cpu();
	return pgd_table;
}

static int ptdump_show(struct seq_file *s, void *v)
{
	pgd_t *pgd_table;
	/* Address space markers hints.
	 * Use a local variable as some macros are not compile-time constants.
	 */
	struct addr_marker address_markers[] = {
		/* { 0, "User Space" }, */

#ifdef CONFIG_ARM

		{ MODULES_VADDR,        "Modules" },
		{ PAGE_OFFSET,          "Kernel Mapping" },
		{ VMALLOC_START,        "vmalloc() Area" },
		{ VMALLOC_END,          "vmalloc() End" },
		{ FIXADDR_START,        "Fixmap Area" },

#elif defined(CONFIG_X86_64)

		{ 0xffff800000000000UL, "Kernel Space" },
		{ PAGE_OFFSET,          "Low Kernel Mapping" },
		{ VMALLOC_START,        "vmalloc() Area" },
		{ VMEMMAP_START,        "Vmemmap" },
# if defined(CONFIG_X86_ESPFIX64) && defined(ESPFIX_BASE_ADDR)
		{ ESPFIX_BASE_ADDR,     "ESPfix Area", 16 },
# endif
# if defined(CONFIG_EFI) && defined(EFI_VA_END)
		{ EFI_VA_END,           "EFI Runtime Services" },
# endif
		{ __START_KERNEL_map,   "High Kernel Mapping" },
		{ MODULES_VADDR,        "Modules" },
		{ MODULES_END,          "End Modules" },
		{ FIXADDR_START,        "Fixmap Area" },

#elif defined(CONFIG_X86_32)

		{ PAGE_OFFSET,          "Kernel Mapping" },
		{ VMALLOC_START,        "vmalloc() Area" },
		{ VMALLOC_END,          "vmalloc() End" },
# ifdef CONFIG_HIGHMEM
		{ PKMAP_BASE,           "Persistent kmap() Area" },
# endif
		{ FIXADDR_START,        "Fixmap Area" },
#endif

		{ -1UL, NULL }		/* End of list */
	};
	struct pg_state st = {
		.seq = s,
		.marker = address_markers,
	};

	show_address_comp(s);
	pgd_table = get_pgd_address(s);
	walk_pgd(&st, pgd_table);
	return 0;
}

static int ptdump_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ptdump_show, NULL);
}

static const struct file_operations ptdump_fops = {
	.open		= ptdump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/**
 * Create a device node with only user-read permission
 */
# if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
/* (struct class*)->devnode prototype has been changed in Linux 3.3 by commit
 * 2c9ede55ecec ("switch device_get_devnode() and ->devnode() to umode_t *")
 */
static char *ptdump_class_devnode(struct device *dev, umode_t *mode)
#else
static char *ptdump_class_devnode(struct device *dev, mode_t *mode)
#endif
{
	/* mode is NULL when devtmpfs_delete_node calls device_get_devnode */
	if (mode)
		*mode = 0400;
	return kstrdup(dev_name(dev), GFP_KERNEL);
}

/* By default, use 0 to dynamically allocate a major number. It will for
 * example allocate a number between 240 and 254, which is advertised as
 * "LOCAL/EXPERIMENTAL USE" in Documentation/devices.txt.
 * Make the chose major number available to userspace through
 * /sys/module/pagetables/parameters/chrdev_major .
 * It is also available in /proc/devices.
 */
static int chrdev_major;
module_param(chrdev_major, uint, 0444);
MODULE_PARM_DESC(chrdev_major, "Character device major number to use");

static struct dentry *debugfs_pe;
static struct class *chrdev_class;

static int __init pt_dump_init(void)
{
	int result;
	struct device *dev;

	/* Create a debugfs file */
	debugfs_pe = debugfs_create_file("kernel_pagetables", 0400, NULL,
					 NULL, &ptdump_fops);
	if (!debugfs_pe)
		return -ENOMEM;

	/* Create a device so that it is available on kernels without
	 * CONFIG_DEBUG_FS
	 */
	chrdev_major = register_chrdev(chrdev_major, "pagetables",
				       &ptdump_fops);
	if (chrdev_major < 0) {
		result = chrdev_major;
		goto error_debugfs;
	}

	/* Create /sys/class/pagetables */
	chrdev_class = class_create(THIS_MODULE, "pagetables");
	if (IS_ERR(chrdev_class)) {
		result = PTR_ERR(chrdev_class);
		goto error_chrdev;
	}
	chrdev_class->devnode = ptdump_class_devnode;

	/* Create /dev/kernel_pagetables and
	 * /sys/devices/virtual/pagetables/kernel_pagetables
	 */
	dev = device_create(chrdev_class, NULL, MKDEV(chrdev_major, 0), NULL,
			    "kernel_pagetables");
	if (IS_ERR(dev)) {
		result = PTR_ERR(dev);
		goto error_class;
	}
	pr_info("created /dev/%s with major number %d\n", dev_name(dev),
		chrdev_major);
	return 0;

error_class:
	class_destroy(chrdev_class);
error_chrdev:
	unregister_chrdev(chrdev_major, "pagetables");
error_debugfs:
	debugfs_remove(debugfs_pe);
	return result;
}

static void __exit pt_dump_exit(void)
{
	device_destroy(chrdev_class, MKDEV(chrdev_major, 0));
	class_destroy(chrdev_class);
	unregister_chrdev(chrdev_major, "pagetables");
	debugfs_remove(debugfs_pe);
}

module_init(pt_dump_init);
module_exit(pt_dump_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Iooss");
MODULE_DESCRIPTION("Dump kernel memory page tables");
