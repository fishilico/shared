/**
 * Windows-specific functions to handle an access violation
 *
 * Documentation:
 * * http://www.microsoft.com/msj/0197/exception/exception.aspx
 *   A Crash Course on the Depths of Win32 (TM) Structured Exception Handling
 * * http://www.nynaeve.net/?p=99
 *   Programming against the x64 exception handling support, part 1
 * * http://sourceforge.net/p/mingw-w64/code/HEAD/tree/trunk/mingw-w64-headers/crt/excpt.h
 *   MinGW-w64 header file for Structured Exception Handling
 * * http://syprog.blogspot.fr/2011/10/windows-structured-and-vectored.html
 *   Windows Structured and Vectored Exception Handling Mechanisms
 *
 * With wine, use WINEDEBUG="trace+seh" to debug exception handling system.
 */
#include "recover_segfault.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <windows.h>

static const BOOL verbose = FALSE;

static const struct segfault_memcontent *g_memmap;
static size_t g_memmap_len;

static LONG NTAPI veh_handler(EXCEPTION_POINTERS *ExceptionPointers)
{
    EXCEPTION_RECORD *ExceptionRecord = ExceptionPointers->ExceptionRecord;
    CONTEXT *ContextRecord = ExceptionPointers->ContextRecord;
    ULONG_PTR data_addr;
    size_t i, j;

    if (ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        fprintf(stderr, "Unhandled exception code 0x%lx\n", ExceptionRecord->ExceptionCode);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ExceptionRecord->ExceptionFlags & EXCEPTION_UNWINDING) {
        fprintf(stderr, "Ignoring exception unwinding\n");
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
        fprintf(stderr, "Ignoring non-continuable exception\n");
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ExceptionRecord->ExceptionFlags) {
        fprintf(stderr, "Unknown exception flags: 0x%lx\n", ExceptionRecord->ExceptionFlags);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ExceptionRecord->NumberParameters < 2) {
        fprintf(stderr, "Not enough parameters for access violation\n");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    data_addr = ExceptionRecord->ExceptionInformation[1];

    if (verbose) {
        fprintf(stderr, "Exception @%p while attempting to %s 0x%p\n",
                ExceptionRecord->ExceptionAddress,
                (ExceptionRecord->ExceptionInformation[0] == 0) ? "read" :
                (ExceptionRecord->ExceptionInformation[0] == 1) ? "write" :
                (ExceptionRecord->ExceptionInformation[0] == 8) ? "execute" : "???",
                (void *)data_addr);
    }

    for (i = 0; i < g_memmap_len; i++) {
        ULONG_PTR memaddr = g_memmap[i].addr;
        size_t memsize = g_memmap[i].size;
        const uint8_t *ptr_instruction;

        if (memaddr <= data_addr && data_addr < memaddr + memsize) {
            /* Found a memory range which contains the faulting address */
            /* Fix instruction pointer */
#if defined(__x86_64__)
            ContextRecord->Rip = (ULONG_PTR)(ExceptionRecord->ExceptionAddress);
#elif defined(__i386__)
            ContextRecord->Eip = (ULONG_PTR)(ExceptionRecord->ExceptionAddress);
#else
#    error "Unknown target architecture"
#endif
            if (run_mov_asm_instruction(ContextRecord,
                                        data_addr,
                                        &(g_memmap[i].data[data_addr - memaddr]),
                                        memsize - (data_addr - memaddr))) {
                /* Intruction pointer has been updated. Resume execution */
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            fprintf(stderr, "Running unknown instruction. Crash!\n");
            ptr_instruction = (uint8_t *)ExceptionRecord->ExceptionAddress;
            fprintf(stderr, "Faulting instruction @%p:", ptr_instruction);
            for (j = 0; j < 16; j++) {
                fprintf(stderr, " %02x", ptr_instruction[j]);
            }
            fprintf(stderr, "\n");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    fprintf(stderr, "Unhandled segmentation fault at %p\n", ExceptionRecord->ExceptionAddress);
    return EXCEPTION_CONTINUE_SEARCH;
}

int run_with_segfault_handler(const struct segfault_memcontent *memmap, size_t len, int (*fct) (void *), void *data)
{
    PVOID handler;
    int retval;

    /* This function is not re-entrant */
    assert(!g_memmap);
    g_memmap = memmap;
    g_memmap_len = len;

    /* Setup SEH, which does not work */
#if 0
#if defined(__x86_64__)
    /* Fill a SCOPE_TABLE_AMD64 structure, with code from MinGW-w64 excpt.h include file
     * Use: LONG NTAPI x86_64_seh_handler(EXCEPTION_POINTERS *ExceptionPointers, ULONG64 EstablisherFrame)
     *      = EXCEPTION_CONTINUE_EXECUTION|EXCEPTION_CONTINUE_SEARCH
     */
    __asm__ volatile (
        ".l_startw:\n"
        ".seh_handler __C_specific_handler, @except\n"
        ".seh_handlerdata\n"
        ".long 1\n"
        ".rva .l_startw, .l_endw, x86_64_seh_handler ,.l_endw\n"
        ".text");
    (void)except_reg;
#elif defined(__i386__)
    /* Framed exceptions, use:
     * * EXCEPTION_REGISTRATION except_reg;
     * * EXCEPTION_DISPOSITION NTAPI x86_32_seh_handler(
     * *     EXCEPTION_RECORD *ExceptionRecord,
     * *     PVOID EstablisherFrame,
     * *     CONTEXT *ContextRecord,
     * *     PVOID DispatcherContext) = ExceptionContinueExecution|ExceptionContinueSearch
     */
    except_reg.handler = &x86_32_seh_handler;
    __asm__ volatile ("movl %%fs:0, %0" : "=r" (except_reg.prev));
    __asm__ volatile ("movl %0, %%fs:0" : : "r" (&except_reg));
#else
#    error "Unknown target architecture"
#endif
#endif /* Disabled SEH */

    /* Use Vectored Exception Handling */
    handler = AddVectoredExceptionHandler(1, veh_handler);
    if (!handler) {
        fprintf(stderr, "AddVectoredExceptionHandler: error %lu\n", GetLastError());
        return 1;
    }

    retval = (*fct) (data);

#if 0
#if defined(__x86_64__)
    __asm__ volatile (
        "nop\n" \
        ".l_endw: nop\n");
#elif defined(__i386__)
    __asm__ volatile ("movl %0, %%fs:0" : : "r" (except_reg.prev));
#else
#    error "Unknown target architecture"
#endif
#endif /* Disabled SEH */
    RemoveVectoredExceptionHandler(handler);
    return retval;
}
