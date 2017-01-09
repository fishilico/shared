/**
 * Test antidebug features
 *
 * Related projects, which detects virtualization:
 * * https://github.com/a0rtega/pafish/tree/master/pafish Pafish
 *
 * Other links:
 * * http://pferrie.host22.com/papers/antidebug.pdf
 *   The "Ultimate" Anti-Debugging Reference
 */
#if !defined(_GNU_SOURCE) && (defined(__linux__) || defined(__unix__) || defined(__posix__))
#    define _GNU_SOURCE /* for syscall */
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
#    define IS_WINDOWS 1
#    include <windows.h>
#endif

#if defined(__linux__) || defined(__unix__) || defined(__posix__)
#    define IS_POSIX 1
#    include <errno.h>
#    include <sys/ptrace.h>
#    include <sys/syscall.h>
#    include <unistd.h>
#endif

#ifndef IS_WINDOWS
#    define IS_WINDOWS 0
#endif
#ifndef IS_POSIX
#    define IS_POSIX 0
#endif

/**
 * Example of simple function which is protected from breakpoints.
 * Use asm to also mark the function end, after the return statement, so that
 * all of its instructions can be checked for breakpoints.
 *
 * To implement this function for a new architecture, run something like:
 * echo 'int f(int v){return v^42;}'|gcc -O2 -xc - -S -o /dev/stdout
 */
int sensitive_computation(int value);
extern uint8_t sensitive_start[];
extern uint8_t sensitive_end[];
__asm__ (
"        .text\n"
/* Define symbols both with and without underscore prefix to match the C name */
"        .globl sensitive_start\n"
"        .globl _sensitive_start\n"
"        .globl sensitive_computation\n"
"        .globl _sensitive_computation\n"
"        .globl sensitive_end\n"
"        .globl _sensitive_end\n"
"sensitive_start:\n"
"_sensitive_start:\n"
#if defined(__x86_64__) || defined(__i386__)
"        .align 16, 0x90\n"
"sensitive_computation:\n"
"_sensitive_computation:\n"
#    if defined(__x86_64__) && IS_POSIX
"        movl %edi, %eax\n" /* First parameter is rdi */
#    elif defined(__x86_64__) && IS_WINDOWS
"        movl %ecx, %eax\n" /* AMD64 Windows stdcall: first parameter is rcx */
#    elif defined(__i386__)
"        movl 4(%esp), %eax\n" /* First parameter is on the stack */
#    endif
"        xorl $42, %eax\n" /* Return value is eax */
"        ret\n"
#elif defined(__arm__)
"        .align 2\n"
"sensitive_computation:\n"
"_sensitive_computation:\n"
"        eor r0, r0, #42\n" /* First parameter and return value are r0 */
"        bx lr\n"
#else
#    error "Unknown target architecture"
#endif
"sensitive_end:\n"
"_sensitive_end:\n"
);

/**
 * Return values:
 * * 0: everything went fine, the program is not being debugged.
 * * 1: something went wrong, an error occured.
 * * 2: the program is being lightly debugged/traced.
 * * 3: all anti-debug tests were triggered (useful for testing purposes).
 */
int main(void)
{
    int is_debugged = 0, is_all_triggered = 1;
    uint8_t *pcode;
#if defined(__arm__)
    /* ARM breakpoint is an undefined instruction.
     * See BREAKINST_ARM and BREAKINST_THUMB macros in
     * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/arm/kernel/ptrace.c
     * Use integers instead of binary strings to use compiler endianness
     */
    const uint32_t arm_break = 0xe7f001f0;
    const uint16_t thumb_break = 0xde01;
    const uint16_t thumb2_break[2] = {0xf7f0, 0xa000};
#endif
#if IS_WINDOWS
    HMODULE hKernel32, hNtDll;
    BOOL (WINAPI *pfnIsDebuggerPresent)(VOID);
    LONG (WINAPI *pfnNtQueryInformationProcess)(HANDLE, int, PVOID, ULONG, PULONG);
    const BYTE *pPeb = NULL;
    BOOL bDebuggerPresent = TRUE;
    LONG status;
    DWORD_PTR dwpDebuggerPresent = 1;
#endif

    /* Check the sensitive function for breakpoints */
    assert(sensitive_start < sensitive_end);
    for (pcode = sensitive_start; pcode < sensitive_end; pcode++) {
#if defined(__x86_64__) || defined(__i386__)
        if (*pcode == 0xcc) {
            printf("[-] int3 instruction detected at %p\n", (void *)pcode);
            is_debugged = 1;
            break;
        }
        if (pcode + 1 < sensitive_end && *pcode == 0xcd && *(pcode + 1) == 0x03) {
            printf("[-] int 3 instruction detected at %p\n", (void *)pcode);
            is_debugged = 1;
            break;
        }
#elif defined(__arm__)
        if (!((uintptr_t)pcode & 3) && !memcmp(pcode, &arm_break, 4)) {
            printf("[-] ARM break instruction detected at %p\n", (void *)pcode);
            is_debugged = 1;
            break;
        }
        if (!((uintptr_t)pcode & 1) && !memcmp(pcode, &thumb_break, 2)) {
            printf("[-] Thumb break instruction detected at %p\n", (void *)pcode);
            is_debugged = 1;
            break;
        }
        if (!((uintptr_t)pcode & 3) && !memcmp(pcode, &thumb2_break, 4)) {
            printf("[-] Thumb2 break instruction detected at %p\n", (void *)pcode);
            is_debugged = 1;
            break;
        }
#else
#    warning "Unknown breakpoints for target architecture"
#endif
    }
    if (pcode == sensitive_end) {
        if (sensitive_computation(260) == 302) {
            printf("[+] sensitive_computation looks fine.\n");
            is_all_triggered = 0;
        } else {
            fprintf(stderr, "[!] sensitive_computation gave an unexpected result.\n");
            return 1;
        }
    }

#if IS_POSIX
    /* Use ptrace syscall to detect tracers
     * Don't use ptrace(PTRACE_TRACEME, 0, NULL, NULL) as this could be overrided.
     */
    if (syscall(__NR_ptrace, PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        if (errno == EPERM) {
            printf("[-] ptrace(TRACEME) failed. Someone is tracing us.\n");
            is_debugged = 1;
        } else {
            perror("[!] ptrace(TRACEME)");
            return 1;
        }
    } else if (syscall(__NR_ptrace, PTRACE_TRACEME, 0, NULL, NULL) == 0) {
        /* As this test can still be avoided with seccomp filters, or more
         * simply with gdb "catch syscall ptrace", test a second time.
         */
        printf("[-] ptrace(TRACEME) succeeded two times. I don't buy it.\n");
        is_debugged = 1;
    } else if (errno != EPERM) {
        perror("[!] ptrace(TRACEME)");
        return 1;
    } else {
        printf("[+] ptrace(TRACEME) ok.\n");
        is_all_triggered = 0;
    }
#endif

#if IS_WINDOWS
    /* Use Windows API, if available */
    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    pfnIsDebuggerPresent = (BOOL (WINAPI *)(VOID))GetProcAddress(hKernel32, "IsDebuggerPresent");
    if (!pfnIsDebuggerPresent) {
        printf("[ ] Kernel32!IsDebuggerPresent does not exist.\n");
    } else if (pfnIsDebuggerPresent()) {
        printf("[-] IsDebuggerPresent said there is a debugger.\n");
        is_debugged = 1;
    } else {
        printf("[+] IsDebuggerPresent returned false.\n");
        is_all_triggered = 0;
    }

    /* Read the BeingDebugged field of the process environment block.
     * It is a byte at offset 2.
     */
#    if defined(__x86_64__)
    __asm__ ("movq %%gs:96, %0" : "=r" (pPeb));
#    elif defined(__i386__)
    __asm__ ("movl %%fs:48, %0" : "=r" (pPeb));
#    else
#        warning "Unknwon way to get the PEB on this architecture"
#    endif
    if (!pPeb) {
        printf("[ ] Unable to get the PEB.\n");
    } else if (pPeb[2]) {
        printf("[-] PEB!BeingDebugged is %u.\n", pPeb[2]);
        is_debugged = 1;
    } else {
        printf("[+] PEB!BeingDebugged is false.\n");
        is_all_triggered = 0;
    }

    /* Use CheckRemoteDebuggerPresent, which uses NtQueryInformationProcess */
    if (!CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent)) {
        fprintf(stderr, "[!] CheckRemoteDebuggerPresent failed with error %lu.\n", GetLastError());
        return 1;
    } else if (bDebuggerPresent) {
        printf("[-] CheckRemoteDebuggerPresent is true.\n");
        is_debugged = 1;
    } else {
        printf("[+] CheckRemoteDebuggerPresent is false.\n");
        is_all_triggered = 0;
    }

    /* Use NtQueryInformationProcess directly, with class 7 for ProcessDebugPort */
    hNtDll = GetModuleHandleW(L"ntdll.dll");
    pfnNtQueryInformationProcess = \
        (LONG (WINAPI *)(HANDLE, int, PVOID, ULONG, PULONG)) \
        GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!pfnNtQueryInformationProcess) {
        printf("[ ] ntdll!NtQueryInformationProcess does not exist.\n");
    } else {
        status = pfnNtQueryInformationProcess(GetCurrentProcess(), 7, &dwpDebuggerPresent, sizeof(dwpDebuggerPresent), NULL);
        if (status) {
            fprintf(stderr, "[!] NtQueryInformationProcess failed with error %lu.\n", GetLastError());
            return 1;
        } else if (dwpDebuggerPresent) {
            printf("[-] NtQueryInformationProcess(ProcessDebugPort) returned true.\n");
            is_debugged = 1;
        } else {
            printf("[+] NtQueryInformationProcess(ProcessDebugPort) returned false.\n");
            is_all_triggered = 0;
        }
    }
#endif

    return is_debugged ? (2 + is_all_triggered) : 0;
}
