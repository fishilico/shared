/**
 * Start cmd.exe
 */
#include "internal_structures.h"
#include "noimport_start.h"

static int _main(void)
{
    BOOL (WINAPI *pfnCreateProcessW)(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        WINBOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);
    DWORD (WINAPI *pfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
    BOOL (WINAPI *pfnCloseHandle)(HANDLE hObject);

    WCHAR szCmdLine[] = { L'c', L'm', L'd', L'\0' };
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    /* Retrieve function pointers */
    pfnCreateProcessW = _GetKernel32ProcAddress("CreateProcessW");
    pfnWaitForSingleObject = _GetKernel32ProcAddress("WaitForSingleObject");
    pfnCloseHandle = _GetKernel32ProcAddress("CloseHandle");
    if (!pfnCreateProcessW || !pfnWaitForSingleObject || !pfnCloseHandle) {
        return 1;
    }

    /* Start process */
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    if (!pfnCreateProcessW(NULL, szCmdLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        return 1;
    }

    /* Wait for it */
    pfnWaitForSingleObject(pi.hProcess, INFINITE);
    pfnCloseHandle(pi.hProcess);
    pfnCloseHandle(pi.hThread);
    return 0;
}
