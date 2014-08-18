/**
 * List the currently running processes
 */
#include <assert.h>
#include "common.h"
#include <psapi.h>

/**
 * Wrap EnumProcesses to allocate memory
 */
static BOOL EnumProcessesWithAlloc(PDWORD *ppProcessIds, DWORD *pcbSize)
{
    PDWORD pProcessIds = NULL;
    DWORD cbSize = 4096, cbRet;

    assert(ppProcessIds && pcbSize);
    do {
        pProcessIds = HeapAlloc(GetProcessHeap(), 0, cbSize);
        if (!pProcessIds) {
            print_winerr(_T("HeapAlloc"));
            return FALSE;
        }
        cbRet = 0;
        if (!EnumProcesses(pProcessIds, cbSize, &cbRet)) {
            print_winerr(_T("EnumProcesses"));
            HeapFree(GetProcessHeap(), 0, pProcessIds);
            return FALSE;
        }
        assert(cbRet <= cbSize);
        if (cbRet == cbSize) {
            /* There has not been enough space in the buffer */
            cbSize *= 2;
            HeapFree(GetProcessHeap(), 0, pProcessIds);
            pProcessIds = NULL;
        }
    } while (!pProcessIds);
    *ppProcessIds = pProcessIds;
    *pcbSize = cbRet;
    return TRUE;
}

/**
 * Wrap EnumProcessModules to allocate memory
 */
static BOOL EnumProcessModulesWithAlloc(HANDLE hProcess, HMODULE **pphModules, DWORD *pcbSize)
{
    HMODULE *phModules = NULL;
    DWORD cbSize = 4096, cbRet;

    assert(pphModules && pcbSize);
    do {
        phModules = HeapAlloc(GetProcessHeap(), 0, cbSize);
        if (!phModules) {
            print_winerr(_T("HeapAlloc"));
            return FALSE;
        }
        cbRet = 0;
        if (!EnumProcessModules(hProcess, phModules, cbSize, &cbRet)) {
            print_winerr(_T("HeapAlloc"));
            HeapFree(GetProcessHeap(), 0, phModules);
            return FALSE;
        }
        assert(cbRet <= cbSize);
        if (cbRet == cbSize) {
            /* There has not been enough space in the buffer */
            cbSize *= 2;
            HeapFree(GetProcessHeap(), 0, phModules);
            phModules = NULL;
        }
    } while (!phModules);
    *pphModules = phModules;
    *pcbSize = cbRet;
    return TRUE;
}

int _tmain()
{
    PDWORD pProcessIds = NULL;
    DWORD cbSize = 0, nProcesses, nModules, i, j, cchLen;
    HANDLE hProcess;
    HMODULE *phModules;
    TCHAR szModBaseName[MAX_PATH], szModPath[MAX_PATH];

    if (!EnumProcessesWithAlloc(&pProcessIds, &cbSize)) {
        return 1;
    }
    nProcesses = cbSize / sizeof(DWORD);
    for (i = 0; i < nProcesses; i++) {
        DWORD dwPid = pProcessIds[i];
        if (!dwPid) {
            _tprintf(_T("PID %lu: skipped\n"), dwPid);
            continue;
        }
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
        if(!hProcess) {
            if (GetLastError() == ERROR_ACCESS_DENIED) {
                _tprintf(_T("%lu: access denied\n"), dwPid);
            } else {
                _ftprintf(stderr, _T("%lu: access error:\n"), dwPid);
                print_winerr(_T("OpenProcess"));
            }
            continue;
        }

        if (!EnumProcessModulesWithAlloc(hProcess, &phModules, &cbSize)) {
            _ftprintf(stderr, _T("%lu: failed to enumerate modules\n"), dwPid);
            CloseHandle(hProcess);
            continue;
        }
        nModules = cbSize / sizeof(HMODULE);
        printf("* PID %lu: %lu modules\n", dwPid, nModules);
        for (j = 0; j < nModules; j++) {
            HMODULE hMod = phModules[j];
            cchLen = GetModuleBaseName(hProcess, hMod, szModBaseName, ARRAYSIZE(szModBaseName));
            if (!cchLen) {
                print_winerr(_T("GetModuleBaseName"));
                continue;
            }
            assert(cchLen < ARRAYSIZE(szModBaseName));
            assert(szModBaseName[cchLen] == 0);

            cchLen = GetModuleFileNameEx(hProcess, hMod, szModPath, ARRAYSIZE(szModPath));
            if (!cchLen) {
                print_winerr(_T("GetModuleFileNameEx"));
                continue;
            }
            assert(cchLen < ARRAYSIZE(szModPath));
            assert(szModPath[cchLen] == 0);

            _tprintf(_T("  - @%p: %s (%s)\n"), hMod, szModBaseName, szModPath);
        }
        HeapFree(GetProcessHeap(), 0, phModules);
        CloseHandle(hProcess);
    }
    HeapFree(GetProcessHeap(), 0, pProcessIds);
    return 0;
}
