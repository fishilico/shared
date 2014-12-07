/**
 * This files defines a few things which are needed when analyzing Linux with
 * Frama-C, which does not understand linker scripts.
 * It defines things coming from the linker script or from asm code.
 */
#ifndef __FRAMAC__
#error This file is only supposed to be used with frama-C
#endif

#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/tracepoint.h>
#include <net/neighbour.h>
#include <net/net_namespace.h>

/**
 * Define references to unsized arrays used in the code.
 * This is done because Frama-C does not support sizeless arrays
 *
 * shell script:
UNAME_R=$(uname -r | cut -d- -f1)
gcc -E - < out-linux-$UNAME_R/arch/um/kernel/vmlinux.lds | \
    sed -e 's/\([{;]\)/\1\n/g' -e 's/\t/ /g' | \
    sed -n 's,\(.* \)\?\([a-zA-Z0-9_]\+\) = \.;.*,\2,p' | \
while read SYM ; do
    TYPE1="$(grep --exclude-dir=.pc "extern .* $SYM\\[\\]" -r src-linux-$UNAME_R \
           | sed -n 's,.*extern \+\(\(const \)\?\(struct \)\?\(unsigned \)\?[a-zA-Z0-9_*]\+\) .*,\1,p' | sort -u)"
    if [ -n "$TYPE1" ] ; then
        if [ $(echo "$TYPE1" | wc -l) -gt 1 ]
        then
            echo '/'"* $SYM has several types:"
            echo "$TYPE1" | sed 's,^, * ,'
            echo ' *'"/"
        fi
        echo $(echo "$TYPE1" |head -n1) $SYM'[1];'
        continue
    fi
    echo '/'"* $SYM not found *"'/'
done
 */
/* __binary_start not found */
char _text[1];
char _sinittext[1];
char _einittext[1];
char _stext[1];
char __sched_text_start[1];
char __sched_text_end[1];
char __lock_text_start[1];
char __lock_text_end[1];
/* __syscall_stub_start not found */
/* __syscall_stub_end not found */
char _etext[1];
char _sdata[1];
char __start_rodata[1];
struct tracepoint __start___tracepoints_ptrs[1];
struct tracepoint __stop___tracepoints_ptrs[1];
#ifdef CONFIG_GENERIC_BUG
const struct bug_entry __start___bug_table[1];
const struct bug_entry __stop___bug_table[1];
#endif
struct pci_fixup __start_pci_fixups_early[1];
struct pci_fixup __end_pci_fixups_early[1];
struct pci_fixup __start_pci_fixups_header[1];
struct pci_fixup __end_pci_fixups_header[1];
struct pci_fixup __start_pci_fixups_final[1];
struct pci_fixup __end_pci_fixups_final[1];
struct pci_fixup __start_pci_fixups_enable[1];
struct pci_fixup __end_pci_fixups_enable[1];
struct pci_fixup __start_pci_fixups_resume[1];
struct pci_fixup __end_pci_fixups_resume[1];
struct pci_fixup __start_pci_fixups_resume_early[1];
struct pci_fixup __end_pci_fixups_resume_early[1];
struct pci_fixup __start_pci_fixups_suspend[1];
struct pci_fixup __end_pci_fixups_suspend[1];
struct builtin_fw __start_builtin_fw[1];
struct builtin_fw __end_builtin_fw[1];
const struct kernel_symbol __start___ksymtab[1];
const struct kernel_symbol __stop___ksymtab[1];
const struct kernel_symbol __start___ksymtab_gpl[1];
const struct kernel_symbol __stop___ksymtab_gpl[1];
const struct kernel_symbol __start___ksymtab_unused[1];
const struct kernel_symbol __stop___ksymtab_unused[1];
const struct kernel_symbol __start___ksymtab_unused_gpl[1];
const struct kernel_symbol __stop___ksymtab_unused_gpl[1];
const struct kernel_symbol __start___ksymtab_gpl_future[1];
const struct kernel_symbol __stop___ksymtab_gpl_future[1];
const unsigned long __start___kcrctab[1];
/* __stop___kcrctab not found */
const unsigned long __start___kcrctab_gpl[1];
/* __stop___kcrctab_gpl not found */
const unsigned long __start___kcrctab_unused[1];
/* __stop___kcrctab_unused not found */
const unsigned long __start___kcrctab_unused_gpl[1];
/* __stop___kcrctab_unused_gpl not found */
const unsigned long __start___kcrctab_gpl_future[1];
/* __stop___kcrctab_gpl_future not found */
const struct kernel_param __start___param[1];
const struct kernel_param __stop___param[1];
/* __start___modver not found */
/* __stop___modver not found */
char __end_rodata[1];
struct exception_table_entry __start___ex_table[1];
struct exception_table_entry __stop___ex_table[1];
/* __uml_setup_start not found */
/* __uml_setup_end not found */
/* __uml_help_start not found */
/* __uml_help_end not found */
/* __uml_postsetup_start not found */
/* __uml_postsetup_end not found */
const struct obs_kernel_param __setup_start[1];
const struct obs_kernel_param __setup_end[1];
char __per_cpu_load[1];
char __per_cpu_start[1];
char __per_cpu_end[1];
initcall_t __initcall_start[1];
initcall_t __initcall0_start[1];
initcall_t __initcall1_start[1];
initcall_t __initcall2_start[1];
initcall_t __initcall3_start[1];
initcall_t __initcall4_start[1];
initcall_t __initcall5_start[1];
/* __initcallrootfs_start not found */
initcall_t __initcall6_start[1];
initcall_t __initcall7_start[1];
initcall_t __initcall_end[1];
initcall_t __con_initcall_start[1];
initcall_t __con_initcall_end[1];
/* __uml_initcall_start not found */
/* __uml_initcall_end not found */
initcall_t __security_initcall_start[1];
initcall_t __security_initcall_end[1];
/* __exitcall_begin not found */
/* __exitcall_end not found */
/* __uml_exitcall_begin not found */
/* __uml_exitcall_end not found */
struct alt_instr __alt_instructions[1];
struct alt_instr __alt_instructions_end[1];
/* __preinit_array_start not found */
/* __preinit_array_end not found */
/* __init_array_start not found */
/* __init_array_end not found */
/* __fini_array_start not found */
/* __fini_array_end not found */
char __init_begin[1];
char __dtb_start[1];
char __dtb_end[1];
char __init_end[1];
#ifdef CONFIG_JUMP_LABEL
struct jump_entry __start___jump_table[1];
struct jump_entry __stop___jump_table[1];
#endif
struct _ddebug __start___verbose[1];
struct _ddebug __stop___verbose[1];
char _edata[1];
char __bss_start[1];
char __bss_stop[1];
char _end[1];

/* Others */
/* include/asm-generic/sections.h */
char __kprobes_text_start[1], __kprobes_text_end[1];
char __entry_text_start[1], __entry_text_end[1];

/* Needed global variables, which are disabled by config */
/* net/core/net_namespace.c */
#ifndef CONFIG_NET
struct net init_net = {
    .dev_base_head = LIST_HEAD_INIT(init_net.dev_base_head),
};
#endif

/* drivers/pci/pci.c */
#ifndef CONFIG_PCI
const char *pci_power_names[] = {
    "error", "D0", "D1", "D2", "D3hot", "D3cold", "unknown",
};
#endif

/* net/ipv6/ndisc.c */
#ifndef CONFIG_IPV6
struct neigh_table nd_tbl = {};
#endif

/* Stub functions for interacting with userspace */
/* arch/um/os-Linux/signal.c */
static int signals_enabled;
void block_signals(void)
{
    signals_enabled = 0;
}
void unblock_signals(void)
{
    signals_enabled = 1;
}
int get_signals(void)
{
    return signals_enabled;
}
int set_signals(int enable)
{
    int ret = signals_enabled;
    signals_enabled = enable;
    return ret;
}
int os_is_signal_stack(void)
{
    return 0;
}
