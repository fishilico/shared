/**
 * Display "Hello, world!" in a message box, without anything in the import table
 */
#include "internal_structures.h"

/**
 * Depending on the chosen subsystem at link-time, the entry point has different names
 *
 * More information on how binutils' ld find the entry point can be get by
 * reading the code of the set_entry_point() function in ld/emultempl/pe.em:
 * https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=ld/emultempl/pe.em
 */
void __cdecl WinMainCRTStartup(void) __attribute__ ((alias("_start")));
void __cdecl mainCRTStartup(void) __attribute__ ((alias("_start")));
void __cdecl _start(void) __attribute__((noreturn));
static int _main(void);

void __cdecl _start(void)
{
    int status = _main();
    while (TRUE) {
        _ExitProcess(status);
    }
}

/**
 * Common entry point
 */
static int _main(void)
{
    int (WINAPI *pfnMessageBoxW)(HWND hWnd, PCWSTR lpText, LPCWSTR lpCaption, UINT uType);
    BOOL (WINAPI *pfnAllocConsole)(void);
    BOOL (WINAPI *pfnFreeConsole)(void);
    HANDLE (WINAPI *pfnGetStdHandle)(IN DWORD nStdHandle);
    BOOL (WINAPI *pfnWriteFile)(
        HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
    const char helloworld[] = "Hello, world!\n";

    HMODULE hModule, hStdOut;
    hModule = _LoadLibraryW(L"user32.dll");
    if (!hModule) {
        return 1;
    }
    pfnMessageBoxW = _GetProcAddress(hModule, "MessageBoxW");
    if (!pfnMessageBoxW) {
        return 1;
    }

    pfnAllocConsole = _GetKernel32ProcAddress("AllocConsole");
    pfnFreeConsole = _GetKernel32ProcAddress("FreeConsole");
    pfnGetStdHandle = _GetKernel32ProcAddress("GetStdHandle");
    pfnWriteFile = _GetKernel32ProcAddress("WriteFile");

    /* Open a console, even when using the windows subsystem */
    if (pfnAllocConsole && pfnGetStdHandle && pfnWriteFile) {
        pfnAllocConsole();
        hStdOut = pfnGetStdHandle(STD_OUTPUT_HANDLE);
        pfnWriteFile(hStdOut, helloworld, sizeof(helloworld) - 1, NULL, NULL);
    }

    pfnMessageBoxW(NULL, L"Hello, world!", L"Hello world box", MB_ICONINFORMATION | MB_OK);
    _FreeLibrary(hModule);
    if (pfnFreeConsole) {
        pfnFreeConsole();
    }
    return 0;
}