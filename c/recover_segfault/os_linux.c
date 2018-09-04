/**
 * Linux-specific functions to handle a segmentation fault
 *
 * Some documentation:
 * * http://feepingcreature.github.io/handling.html
 *   Cleanly recovering from Segfaults under Windows and Linux (32-bit, x86)
 */
#include "recover_segfault.h"

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

static struct segfault_memcontent *g_memmap;
static size_t g_memmap_len;

static void sigsegv_sigaction(int s, siginfo_t *info, void *context)
{
    ucontext_t *ctx = (ucontext_t *)context;
    uintptr_t data_addr;
    size_t i, j;

    assert(g_memmap && g_memmap_len);
    assert(s == SIGSEGV);
    assert(info != NULL && info->si_signo == SIGSEGV);

    data_addr = (uintptr_t)info->si_addr;
    for (i = 0; i < g_memmap_len; i++) {
        uintptr_t memaddr = g_memmap[i].addr;
        size_t memsize = g_memmap[i].size;
        const uint8_t *ptr_instruction;

        if (memaddr <= data_addr && data_addr < memaddr + memsize) {
            /* Found a memory range which contains the faulting address */
            if (run_mov_asm_instruction(&(ctx->uc_mcontext),
                                        data_addr,
                                        &(g_memmap[i].data[data_addr - memaddr]),
                                        memsize - (data_addr - memaddr))) {
                /* Intruction pointer has been updated. Resume execution */
                return;
            }
            fprintf(stderr, "Running unknown instruction. Abort!\n");
#if defined(__x86_64__)
            ptr_instruction = (uint8_t *)ctx->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__)
            ptr_instruction = (uint8_t *)ctx->uc_mcontext.gregs[REG_EIP];
#else
#    error "Unknown target architecture"
#endif
            fprintf(stderr, "Faulting instruction @%p:", (const void *)ptr_instruction);
            for (j = 0; j < 16; j++) {
                fprintf(stderr, " %02x", ptr_instruction[j]);
            }
            fprintf(stderr, "\n");
            abort();
        }
    }
    fprintf(stderr, "Unhandled segmentation fault at %p\n", info->si_addr);
    abort();
}

int run_with_segfault_handler(const struct segfault_memcontent *memmap, size_t len, int (*fct) (void *), void *data)
{
    sigset_t mask;
    struct sigaction act, oldact;
    int retval;

    /* This function must be called only once */
    assert(!g_memmap);
    g_memmap = calloc(len, sizeof(struct segfault_memcontent));
    if (!g_memmap) {
        perror("calloc");
        return 1;
    }
    memcpy(g_memmap, memmap, len * sizeof(struct segfault_memcontent));
    g_memmap_len = len;

    memset(&act, 0, sizeof(act));
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = sigsegv_sigaction;
    if (sigaction(SIGSEGV, &act, &oldact) == -1) {
        perror("sigaction");
        free(g_memmap);
        return 1;
    }

    sigemptyset(&mask);
    sigaddset(&mask, SIGSEGV);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
        perror("sigprocmask");
        free(g_memmap);
        return 1;
    }

    retval = (*fct) (data);

    if (sigaction(SIGSEGV, &oldact, NULL) == -1) {
        perror("sigaction");
    }
    return retval;
}
