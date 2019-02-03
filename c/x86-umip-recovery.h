/**
 * Catch Intel UMIP faults and recover from them.
 *
 * UMIP (User-Mode Instruction Prevention) triggers SIGSEGV when a userspace
 * program tries to use SGDT, SIDT, SLDT, SMSW or STR.
 *
 * Provide some macros to recover from such a fault.
 */

#ifndef X86_UMIP_RECOVERY_H
#define X86_UMIP_RECOVERY_H

static volatile unsigned char g_umip_in_section;

#ifdef __linux__
# include <assert.h>
# include <setjmp.h>
# include <signal.h>
# include <stdlib.h>

static sigjmp_buf g_umip_jmpbuf;

/* Catch a SIGSEGV signal from UMIP */
static void __attribute__((noreturn))
umip_sigsegv_sigaction(int s, siginfo_t *info, void *context __attribute__ ((unused)))
{
    assert(s == SIGSEGV);
    assert(info != NULL && info->si_signo == SIGSEGV);

    /* Crash if SIGSEGV occurred outside of an UMIP section */
    if (!g_umip_in_section) {
        fprintf(stderr, "Error: got SIGSEGV outside of UMIP section\n");
        abort();
    }

    /* Recover */
    siglongjmp(g_umip_jmpbuf, 1);
}

static void configure_umip_recovery(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = umip_sigsegv_sigaction;
    if (sigaction(SIGSEGV, &act, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
}

# define UMIP_SECTION_START(instruction) \
    if (g_umip_in_section = 1, sigsetjmp(g_umip_jmpbuf, SIGSEGV)) { \
        fprintf(stderr, "UMIP error: instruction %s is forbidden.\n", (instruction)); \
        g_umip_in_section = 0; \
    } else {
# define UMIP_SECTION_END \
        g_umip_in_section = 0; \
    }

#else
/* UMIP recovery is not yet supported on other Operating systems */
static void configure_umip_recovery(void)
{
}

# define UMIP_SECTION_START(instruction)
# define UMIP_SECTION_END
#endif

#endif /* X86_UMIP_RECOVERY_H */
