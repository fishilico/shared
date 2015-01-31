/**
 * Display "Hello, world!" in a message box, without anything in the import table
 */
#include "internal_structures.h"
#include "noimport_start.h"

static int _main(void)
{
    int (WINAPI *pfnMessageBoxW)(HWND hWnd, PCWSTR lpText, LPCWSTR lpCaption, UINT uType);
    BOOL (WINAPI *pfnAllocConsole)(void);
    BOOL (WINAPI *pfnFreeConsole)(void);
    HANDLE (WINAPI *pfnGetStdHandle)(DWORD nStdHandle);
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
