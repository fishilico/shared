/**
 * Write code to memory and execute it
 */
#include "common.h"

/**
 * Test whether direct allocation of RWX memory works
 */
static BOOL test_alloc_wx(LPCVOID pCode, SIZE_T cbSize)
{
    LPVOID ptr;
    int result = 42;

    ptr = VirtualAlloc(NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ptr) {
        print_winerr(_T("VirtualAlloc(RWX)"));
        return FALSE;
    }
    _tprintf(_T("RWX VirtualAlloc succeeded at %p.\n"), ptr);
    memcpy(ptr, pCode, cbSize);

    /* Flush CPU cache */
    if (!FlushInstructionCache(GetCurrentProcess(), ptr, cbSize)) {
        print_winerr(_T("FlushInstructionCache"));
        VirtualFree(ptr, 0, MEM_RELEASE);
        return FALSE;
    }
    result = ((int (*)(void))(ULONG_PTR)ptr) ();
    if (!VirtualFree(ptr, 0, MEM_RELEASE)) {
        print_winerr(_T("VirtualFree"));
        return FALSE;
    }
    if (result != 0) {
        _ftprintf(stderr, _T("Error: unexpected result: %d\n"), result);
        return FALSE;
    }
    _tprintf(_T("... Successfully used RWX memory.\n"));
    return TRUE;
}

/**
 * Test whether allocation RW memory and then setting protection to RX works
 */
static BOOL test_alloc_w_protect_x(LPCVOID pCode, SIZE_T cbSize)
{
    LPVOID ptr;
    DWORD dwOldProtect;
    int result;

    ptr = VirtualAlloc(NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        print_winerr(_T("VirtualAlloc(RW)"));
        return FALSE;
    }
    _tprintf(_T("RW VirtualAlloc succeeded at %p.\n"), ptr);
    memcpy(ptr, pCode, cbSize);

    /* Even if it is not used, the last parameter of VirtualProtect must be valid */
    if (!VirtualProtect(ptr, cbSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        print_winerr(_T("VirtualProtect(RX)"));
        VirtualFree(ptr, 0, MEM_RELEASE);
        return FALSE;
    }
    _tprintf(_T("... RX VirtualProtect succeeded.\n"), ptr);
    if (!FlushInstructionCache(GetCurrentProcess(), ptr, cbSize)) {
        print_winerr(_T("FlushInstructionCache"));
        VirtualFree(ptr, 0, MEM_RELEASE);
        return FALSE;
    }
    result = ((int (*)(void))(ULONG_PTR)ptr) ();
    if (!VirtualFree(ptr, 0, MEM_RELEASE)) {
        print_winerr(_T("VirtualFree"));
        return FALSE;
    }
    if (result != 0) {
        _ftprintf(stderr, _T("Error: unexpected result: %d\n"), result);
        return FALSE;
    }
    _tprintf(_T("... Successfully used RW-RX memory.\n"));
    return TRUE;
}

int _tmain(void)
{
#if defined(__i386__) || defined(__x86_64__)
    /**
     * Binary representation of "return 0;" in x86 instruction set:
     *     31 c0      xor    %eax,%eax
     *     c3         ret
     */
    const BYTE ret_zero[] = { 0x31, 0xc0, 0xc3 };
#elif defined(__arm__)
    /**
     * Binary representation of "return 0;" in ARM instruction set, using the
     * endianness of the compiler:
     *     e3a00000     mov r0, #0
     *     e12fff1e     bx  lr
     */
    const uint32_t ret_zero[] = { 0xe3a00000, 0xe12fff1e };
#else
#    error Unsupported architecture
#endif
    int ret = 0;

    if (!test_alloc_wx(ret_zero, sizeof(ret_zero))) {
        ret = 1;
    }
    if (!test_alloc_w_protect_x(ret_zero, sizeof(ret_zero))) {
        ret = 1;
    }
    return ret;
}
