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
void __cdecl _start(void);
static int _main(void);

void __cdecl _start(void)
{
    _ExitProcess(_main());
}

/**
 * Common entry point
 */
static int _main(void)
{
    int (WINAPI *pfnMessageBoxW)(
        IN HWND hWnd OPTIONAL,
        IN LPCWSTR lpText OPTIONAL,
        IN LPCWSTR lpCaption OPTIONAL,
        IN UINT uType
    );
    HMODULE hModule;
    hModule = _LoadLibraryW(L"user32.dll");
    if (!hModule) {
        return 1;
    }
    pfnMessageBoxW = _GetProcAddress(hModule, "MessageBoxW");
    if (!pfnMessageBoxW) {
        return 1;
    }
    pfnMessageBoxW(NULL, L"Hello, world!", L"Hello world box", MB_ICONINFORMATION | MB_OK);
    _FreeLibrary(hModule);
    return 0;
}
