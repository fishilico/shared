/**
 * List the command lines of the currently running processes
 *
 * API documentation:
 *  HANDLE WINAPI CreateRemoteThread(
 *      IN HANDLE hProcess,
 *      IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
 *      IN SIZE_T dwStackSize,
 *      IN LPTHREAD_START_ROUTINE lpStartAddress,
 *      IN LPVOID lpParameter,
 *      IN DWORD dwCreationFlags,
 *      OUT LPDWORD lpThreadId
 *  );
);

 */
#include "common.h"
#include <tlhelp32.h>

int _tmain()
{
    HMODULE hKernel;
    LPTHREAD_START_ROUTINE lpfctGetCmdLine;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hKernel = GetModuleHandle(_T("kernel32.dll"));
    if (!hKernel) {
        print_winerr(_T("GetModuleHandle(kernel32.dll)"));
        return 1;
    }
    lpfctGetCmdLine = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, "GetCommandLineW");
    if (!lpfctGetCmdLine) {
        print_winerr(_T("GetProcAddress(GetCommandLineW)"));
        return 1;
    }

    /* Take a snapshot of processes to enumerate them */
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
        HANDLE hModuleSnap, hProcess, hThread;
        MODULEENTRY32 me32;
        DWORD dwRetAddr;
        WCHAR szCmdLine[MAX_PATH * 8];
        SIZE_T cbRead = 0;

        /* 32-bit applications fail to inject code into 64-bit ones and vice-versa.
         * Such issue can be detected when attempting to enumerate modules.
         */
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
        if (hModuleSnap == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_NOACCESS) {
                /* This happens if I use 32 bits and target uses 64 bits */
                _tprintf(_T("PID %lu (%s): Unable to enumerate modules\n"), pe32.th32ProcessID, pe32.szExeFile);
            } else {
                print_winerr(_T("CreateToolhelp32Snapshot(Module)"));
            }
            continue;
        }
        me32.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(hModuleSnap, &me32)) {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                /* This happens if I use 64 bits and target uses 32 bits */
                _tprintf(_T("PID %lu (%s): Unable to enumerate modules\n"), pe32.th32ProcessID, pe32.szExeFile);
            } else {
                print_winerr(_T("Module32First"));
            }
            CloseHandle(hModuleSnap);
            continue;
        }
        CloseHandle(hModuleSnap);

        /* Spawn a thread inside the process */
        hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            0, pe32.th32ProcessID);
        if(!hProcess) {
            if (GetLastError() != ERROR_ACCESS_DENIED) {
                _ftprintf(stderr, _T("%lu: access error:\n"), pe32.th32ProcessID);
                print_winerr(_T("OpenProcess"));
            }
            continue;
        }
        hThread = CreateRemoteThread(hProcess, NULL, 0, lpfctGetCmdLine, NULL, 0, NULL);
        if (!hThread) {
            print_winerr(_T("CreateRemoteThread"));
            CloseHandle(hProcess);
            continue;
        }
        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &dwRetAddr);
        CloseHandle(hThread);

        /* Assume the address of the command line fits a 32-bit pointer */
        if (!ReadProcessMemory(hProcess, (LPVOID)dwRetAddr, szCmdLine, sizeof(szCmdLine), &cbRead)) {
            print_winerr(_T("ReadProcessMemory"));
            CloseHandle(hProcess);
            continue;
        }
        assert(cbRead <= sizeof(szCmdLine));
        szCmdLine[ARRAYSIZE(szCmdLine) - 1] = 0;
        _tprintf(_T("PID %lu: %s\n"), pe32.th32ProcessID, szCmdLine);
        CloseHandle(hProcess);
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return 0;
}
