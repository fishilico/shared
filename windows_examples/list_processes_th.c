/**
 * List the currently running processes using the Tool Help functions
 */
#include "common.h"
#include <tlhelp32.h>

int _tmain()
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    /* Take a snapshot of all processes in the system */
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        print_winerr(_T("CreateToolhelp32Snapshot(Process)"));
        return 1;
    }
    pe32.dwSize=sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        print_winerr(_T("Process32First"));
        CloseHandle(hProcessSnap);
        return 1;
    }
    do {
        HANDLE hModuleSnap;
        MODULEENTRY32 me32;

        _tprintf(_T("PID %lu, PPID %lu: %s (%ld thread(s))\n"),
            pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.szExeFile, pe32.cntThreads);
        if (!pe32.th32ProcessID) {
            continue;
        }

        /* Take a snapshot of the modules of the given process */
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
        if (hModuleSnap == INVALID_HANDLE_VALUE) {
            print_winerr(_T("CreateToolhelp32Snapshot(Module)"));
            continue;
        }
        me32.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(hModuleSnap, &me32)) {
            print_winerr(_T("Module32First"));
            CloseHandle(hModuleSnap);
            continue;
        }
        do {
            assert(me32.th32ProcessID == pe32.th32ProcessID);
            _tprintf(_T("  - @%p (size 0x%06lx): %s (%s)\n"),
                me32.modBaseAddr, me32.modBaseSize, me32.szModule, me32.szExePath);
        } while (Module32Next(hModuleSnap, &me32));
        CloseHandle(hModuleSnap);
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return 0;
}
