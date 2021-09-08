/**
 * This file is automatically generated.
 * DO NOT EDIT THIS FILE DIRECTLY.
 *
 * NB: designated initializers are a C99 feature so use __extension__ to be
 *   able to compile with -pendantic.
 */

#ifndef CPUID_ENUM_H
#define CPUID_ENUM_H

#include <assert.h>

/**
 * cpuid 0x00000001, edx register
 */
__extension__ static const char* cpuidstr_1_edx[32] = {
    [0] = "fpu",
    [1] = "vme",
    [2] = "de",
    [3] = "pse",
    [4] = "tsc",
    [5] = "msr",
    [6] = "pae",
    [7] = "mce",
    [8] = "cx8",
    [9] = "apic",
    [11] = "sep",
    [12] = "mtrr",
    [13] = "pge",
    [14] = "mca",
    [15] = "cmov",
    [16] = "pat",
    [17] = "pse36",
    [18] = "pn",
    [19] = "clflush",
    [21] = "dts",
    [22] = "acpi",
    [23] = "mmx",
    [24] = "fxsr",
    [25] = "sse",
    [26] = "sse2",
    [27] = "selfsnoop",
    [28] = "ht",
    [29] = "acc",
    [30] = "ia64",
    [31] = "pbe",
};

/**
 * cpuid 0x00000001, ecx register
 */
__extension__ static const char* cpuidstr_1_ecx[32] = {
    [0] = "sse3",
    [1] = "pclmulqdq",
    [2] = "dtes64",
    [3] = "mwait",
    [4] = "dscpl",
    [5] = "vmx",
    [6] = "smx",
    [7] = "est",
    [8] = "tm2",
    [9] = "ssse3",
    [10] = "cid",
    [11] = "sdbg",
    [12] = "fma",
    [13] = "cx16",
    [14] = "xtpr",
    [15] = "pdcm",
    [17] = "pcid",
    [18] = "dca",
    [19] = "sse4_1",
    [20] = "sse4_2",
    [21] = "x2apic",
    [22] = "movbe",
    [23] = "popcnt",
    [24] = "tsc_deadline_timer",
    [25] = "aes",
    [26] = "xsave",
    [27] = "osxsave",
    [28] = "avx",
    [29] = "f16c",
    [30] = "rdrand",
    [31] = "hypervisor",
};

/**
 * cpuid 0x00000006, eax register (Thermal and Power Management Features)
 */
__extension__ static const char* cpuidstr_6_eax[32] = {
    [0] = "dtherm",
    [1] = "ida",
    [2] = "arat",
    [4] = "pln",
    [6] = "pts",
    [7] = "hwp",
    [8] = "hwp_notify",
    [9] = "hwp_act_window",
    [10] = "hwp_epp",
    [11] = "hwp_pkg_req",
};

/**
 * cpuid 0x00000007:0, ebx register
 */
__extension__ static const char* cpuidstr_7_ebx[32] = {
    [0] = "fsgsbase",
    [1] = "tsc_adjust",
    [2] = "sgx",
    [3] = "bmi1",
    [4] = "hle",
    [5] = "avx2",
    [6] = "fdp_excptn_only",
    [7] = "smep",
    [8] = "bmi2",
    [9] = "erms",
    [10] = "invpcid",
    [11] = "rtm",
    [12] = "cqm",
    [13] = "zero_fcs_fds",
    [14] = "mpx",
    [15] = "rdt_a",
    [16] = "avx512f",
    [17] = "avx512dq",
    [18] = "rdseed",
    [19] = "adx",
    [20] = "smap",
    [21] = "avx512ifma",
    [23] = "clflushopt",
    [24] = "clwb",
    [25] = "intel_pt",
    [26] = "avx512pf",
    [27] = "avx512er",
    [28] = "avx512cd",
    [29] = "sha_ni",
    [30] = "avx512bw",
    [31] = "avx512vl",
};

/**
 * cpuid 0x00000007:0, ecx register
 */
__extension__ static const char* cpuidstr_7_ecx[32] = {
    [1] = "avx512vbmi",
    [2] = "umip",
    [3] = "pku",
    [4] = "ospke",
    [5] = "waitpkg",
    [6] = "avx512_vbmi2",
    [8] = "gfni",
    [9] = "vaes",
    [10] = "vpclmulqdq",
    [11] = "avx512_vnni",
    [12] = "avx512_bitalg",
    [13] = "tme",
    [14] = "avx512_vpopcntdq",
    [16] = "la57",
    [22] = "rdpid",
    [24] = "bus_lock_detect",
    [25] = "cldemote",
    [27] = "movdiri",
    [28] = "movdir64b",
    [29] = "enqcmd",
    [30] = "sgx_lc",
};

/**
 * cpuid 0x00000007:0, edx register
 */
__extension__ static const char* cpuidstr_7_edx[32] = {
    [2] = "avx512_4vnniw",
    [3] = "avx512_4fmaps",
    [4] = "fsrm",
    [8] = "avx512_vp2intersect",
    [9] = "srbds_ctrl",
    [10] = "md_clear",
    [11] = "rtm_always_abort",
    [13] = "tsx_force_abort",
    [14] = "serialize",
    [15] = "hybrid_cpu",
    [16] = "tsxldtrk",
    [18] = "pconfig",
    [19] = "arch_lbr",
    [23] = "avx512_fp16",
    [26] = "spec_ctrl",
    [27] = "intel_stibp",
    [28] = "flush_l1d",
    [29] = "arch_capabilities",
    [30] = "core_capabilities",
    [31] = "spec_ctrl_ssbd",
};

/**
 * cpuid 0x80000001, edx register
 */
__extension__ static const char* cpuidstr_ext1_edx[32] = {
    [11] = "syscall",
    [19] = "mp",
    [20] = "nx",
    [22] = "mmxext",
    [25] = "fxsr_opt",
    [26] = "gbpages",
    [27] = "rdtscp",
    [29] = "lm",
    [30] = "3dnowext",
    [31] = "3dnow",
};

/**
 * cpuid 0x80000001, ecx register
 */
__extension__ static const char* cpuidstr_ext1_ecx[32] = {
    [0] = "lahf_lm",
    [1] = "cmp_legacy",
    [2] = "svm",
    [3] = "extapic",
    [4] = "cr8_legacy",
    [5] = "abm",
    [6] = "sse4a",
    [7] = "misalignsse",
    [8] = "3dnowprefetch",
    [9] = "osvw",
    [10] = "ibs",
    [11] = "xop",
    [12] = "skinit",
    [13] = "wdt",
    [15] = "lwp",
    [16] = "fma4",
    [17] = "tce",
    [19] = "nodeid_msr",
    [21] = "tbm",
    [22] = "topoext",
    [23] = "perfctr_core",
    [24] = "perfctr_nb",
    [26] = "bpext",
    [27] = "ptsc",
    [28] = "perfctr_llc",
    [29] = "mwaitx",
};

/**
 * cpuid 0x00000006, ecx register
 */
__extension__ static const char* cpuidstr_6_ecx[32] = {
    [0] = "aperfmperf",
    [3] = "epb",
};

/**
 * cpuid 0x80000007, edx register
 */
__extension__ static const char* cpuidstr_ext7_edx[32] = {
    [7] = "hw_pstate",
    [9] = "cpb",
    [11] = "proc_feedback",
};

static void add_manual_cpuid_str(void)
{
    /* From Intel documentation */
    assert(cpuidstr_6_eax[5] == NULL);
    cpuidstr_6_eax[5] = "emcd"; /* Clock modulation duty cycle extension */
    assert(cpuidstr_6_eax[13] == NULL);
    cpuidstr_6_eax[13] = "hdc";
    assert(cpuidstr_7_ebx[22] == NULL);
    cpuidstr_7_ebx[22] = "pcommit"; /* Deprecated pcommit instruction, Linux commit fd1d961dd681 ("x86/insn: remove pcommit") */

    /* documented in /usr/src/linux/arch/x86/kernel/cpu/{amd.c,intel.c}
     * and also /usr/src/linux/tools/power/x86/turbostat/turbostat.c
     */
    assert(cpuidstr_ext7_edx[8] == NULL);
    cpuidstr_ext7_edx[8] = "constant_tsc";
}

#endif
