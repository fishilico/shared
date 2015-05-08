/**
 * Measure the timing in a segmentation fault/access violation
 *
 * This program counts the number of cycles which are elapsed between an access
 * to a faulty memory location and the execution of a fault handler.
 *
 * By the way, TSX instructions (XBEGIN/XEND) allow probing memory space much
 * quicker, and may be used for example to leak the kernel position:
 * http://labs.bromium.com/2014/10/27/tsx-improves-timing-attacks-against-kaslr/
 * (these instructions are used in glibc in sysdeps/unix/sysv/linux/x86/hle.h
 * and sysdeps/unix/sysv/linux/x86/elision-*).
 */
#if !defined(_GNU_SOURCE) && defined(__linux__)
#    define _GNU_SOURCE /* for sigaction */
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define NUM_SEGV_ITERATIONS_FOR_WARMUP 100
#define NUM_SEGV_ITERATIONS_FOR_MEAN 1000

static volatile uint64_t g_tsc_end;
static volatile unsigned long g_num_segfault;

int main(void);

#ifdef __linux__
#    include <signal.h>
#    include <stdlib.h>
#    include <string.h>
#    include <ucontext.h>

static void sigsegv_readtsc(int s, siginfo_t *info, void *context)
{
    static unsigned long s_dummy_long;
    uint32_t low, high;
    ucontext_t *ctx;

    /* Read the TSC after a segfault occured */
    __asm__ volatile ("rdtsc" : "=a" (low), "=d" (high));
    g_tsc_end = ((uint64_t)high) << 32 | low;

    /* Sanity checks */
    ctx = (ucontext_t *)context;
    assert(s == SIGSEGV);
    assert(info != NULL && info->si_signo == SIGSEGV);
    assert(ctx != NULL);

    g_num_segfault += 1;

    /* Put a valid address into RSI/ESI register, which was used */
#    if defined(__x86_64__)
    ctx->uc_mcontext.gregs[REG_RSI] = (greg_t)&s_dummy_long;
#    elif defined(__i386__)
    ctx->uc_mcontext.gregs[REG_ESI] = (greg_t)&s_dummy_long;
#    else
#        error "Unknown target architecture"
#    endif
}

static void setup_segfault_handler(void)
{
    struct sigaction act;
    sigset_t mask;

    memset(&act, 0, sizeof(act));
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = sigsegv_readtsc;
    if (sigaction(SIGSEGV, &act, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    sigemptyset(&mask);
    sigaddset(&mask, SIGSEGV);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
        perror("sigprocmask");
        exit(1);
    }
}

#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
#    include <windows.h>

static LONG WINAPI vectored_handler_readtsc(EXCEPTION_POINTERS *ExceptionInfo)
{
    static unsigned long s_dummy_long;
    uint32_t low, high;
    EXCEPTION_RECORD *ExceptionRecord = ExceptionInfo->ExceptionRecord;
    CONTEXT *ContextRecord = ExceptionInfo->ContextRecord;

    /* Read the TSC after a access violation occured */
    __asm__ volatile ("rdtsc" : "=a" (low), "=d" (high));
    g_tsc_end = ((uint64_t)high) << 32 | low;

    /* Ignore access violation */
    if (ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    g_num_segfault += 1;

    /* Put a valid address into RSI/ESI register, which was used */
#    if defined(__x86_64__)
    ContextRecord->Rsi = (DWORD64)&s_dummy_long;
#    elif defined(__i386__)
    ContextRecord->Esi = (DWORD)&s_dummy_long;
#    else
#        error "Unknown target architecture"
#    endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void setup_segfault_handler(void)
{
    PVOID handler;

    handler = AddVectoredExceptionHandler(1, vectored_handler_readtsc);
    if (!handler) {
        fprintf(stderr, "AddVectoredExceptionHandler: error %lu\n", GetLastError());
        exit(1);
    }
}

#else
#    error Unknown target OS
#endif

/**
 * Measure the delay of a read and write fault
 */
static bool show_fault_delay(uintptr_t addr, const char *desc)
{
    unsigned int i, dummy;
    uint32_t low, high;
    uint64_t tsc_diff, ncycles_read = 0, ncycles_write = 0;

    /* Warm up the cache */
    g_num_segfault = 0;
    for (i = 0; i < NUM_SEGV_ITERATIONS_FOR_WARMUP; i++) {
        /* Force loading an invalid address in rsi or esi register */
        __asm__ volatile ("movl 0(%[rsi_or_esi]), %[dest]"
            : [dest] "=S" (dummy)
            : [rsi_or_esi] "S" (addr));
    }

    /* Measure only if some faults occured */
    if (g_num_segfault) {
        /* Now, do the measure for real */
        g_num_segfault = 0;
        tsc_diff = 0;
        for (i = 0; i < NUM_SEGV_ITERATIONS_FOR_MEAN; i++) {
            /* Force loading an invalid address in rsi or esi register */
            __asm__ volatile ("rdtsc ; movl 0(%[rsi_or_esi]), %[dest]"
                : "=a" (low), "=d" (high), [dest] "=S" (dummy)
                : [rsi_or_esi] "S" (addr));

            /* The segfault handler modified g_tsc_end */
            tsc_diff += *(volatile uint64_t *)&g_tsc_end - (((uint64_t)high) << 32 | low);
        }
        assert(g_num_segfault == NUM_SEGV_ITERATIONS_FOR_MEAN);
        ncycles_read = tsc_diff / NUM_SEGV_ITERATIONS_FOR_MEAN;
    }

    /* Do the same thing, with write access */
    g_num_segfault = 0;
    for (i = 0; i < NUM_SEGV_ITERATIONS_FOR_WARMUP; i++) {
        __asm__ volatile ("movl $0, 0(%[rsi_or_esi])"
            : "=S" (dummy)
            : [rsi_or_esi] "S" (addr));
    }
    if (g_num_segfault) {
        g_num_segfault = 0;
        tsc_diff = 0;
        for (i = 0; i < NUM_SEGV_ITERATIONS_FOR_MEAN; i++) {
            __asm__ volatile ("rdtsc ; movl $0, 0(%[rsi_or_esi])"
                : "=a" (low), "=d" (high), "=S" (dummy)
                : [rsi_or_esi] "S" (addr));
            tsc_diff += *(volatile uint64_t *)&g_tsc_end - (((uint64_t)high) << 32 | low);
        }
        assert(g_num_segfault == NUM_SEGV_ITERATIONS_FOR_MEAN);
        ncycles_write = tsc_diff / NUM_SEGV_ITERATIONS_FOR_MEAN;
    }

    printf("%*" PRIxPTR ": %5" PRIu64 " %5" PRIu64 " %s\n",
           2 * (int)sizeof(addr), addr,
           ncycles_read, ncycles_write, desc);

    /* Perform some sanity checks */
    if (addr == 0 && (!ncycles_read || !ncycles_write)) {
        fprintf(stderr, "null address access did not fault\n");
        return false;
    }
    if (addr == (uintptr_t)main && ncycles_read) {
        fprintf(stderr, "main address access faulted on read\n");
        return false;
    }
    return true;
}

int main(void)
{
    setup_segfault_handler();

    printf("Number of cycles to catch a segmentation fault (R, W):\n");

    /* Null address */
    if (!show_fault_delay(0, "Null pointer")) {
        return 1;
    }
    show_fault_delay(0x1000, "First page");

    /* Sanity check a fault on a sane address */
    if (!show_fault_delay((uintptr_t)main, "Address of main()")) {
        return 1;
    }

#if defined(__x86_64__)
    /* Hole in addresses */
    show_fault_delay(0x8000000000000000, "Canonical hole");
    show_fault_delay(0xff00000000000000, "Canonical hole");

    /* Linux low kernel mapping, 0xffff880000000000 */
    show_fault_delay(0xffff880000000000, "Linux low kernel mapping");

    /* Linux high kernel mapping, 0xffffffff80000000..0xffffffffc0000000 */
    show_fault_delay(0xffffffff80000000, "Linux high kernel mapping");
#else
    /* Kernel mapping, 0xc0000000 */
    show_fault_delay(0xc0000000, "Kernel mapping");
#endif

    /* Last page */
    show_fault_delay((uintptr_t)-0x1000, "Last page");
    return 0;
}
