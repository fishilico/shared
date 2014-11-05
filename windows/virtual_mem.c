/**
 * Enumerate allocated virtual memory with VirtualQuery
 */
#include "common.h"
#include <inttypes.h>
#include <psapi.h>

/* Describe a protection flag in a string */
static LPCTSTR describe_protect(DWORD dwProt)
{
    switch (dwProt) {
        case 0:
            return _T("---[null]");
        case PAGE_NOACCESS:
            return _T("---");
        case PAGE_READONLY:
            return _T("r--");
        case PAGE_READWRITE:
            return _T("rw-");
        case PAGE_WRITECOPY:
            return _T("rc-");
        case PAGE_EXECUTE:
            return _T("--x");
        case PAGE_EXECUTE_READ:
            return _T("r-x");
        case PAGE_EXECUTE_READWRITE:
            return _T("rwx");
        case PAGE_EXECUTE_WRITECOPY:
            return _T("rcx");
        case PAGE_GUARD | PAGE_READWRITE:
            return _T("rw-[guard]");
        case PAGE_NOCACHE:
            return _T("---[nocache]");
        case PAGE_WRITECOMBINE:
            return _T("---[wr combine]");
    }
    _ftprintf(stderr, _T("Unknown protection flag 0x%x\n"), dwProt);
    return _T("???");
}

/**
 * Wrap GetModuleFileName to allocate memory
 */
static BOOL GetModuleFileNameWithAlloc(HMODULE hModule, LPTSTR *pszFileName)
{
    LPTSTR buffer = NULL;
    DWORD cchSize = 1024, cchRet;

    assert(hModule && pszFileName);
    do {
        buffer = HeapAlloc(GetProcessHeap(), 0, cchSize * sizeof(TCHAR));
        if (!buffer) {
            print_winerr(_T("HeapAlloc"));
            return FALSE;
        }
        cchRet = GetModuleFileName(hModule, buffer, cchSize);
        if (!cchRet) {
            print_winerr(_T("GetModuleFileName"));
            HeapFree(GetProcessHeap(), 0, buffer);
            return FALSE;
        }
        if (cchRet == cchSize) {
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
            cchSize *= 2;
        }
        assert(cchRet <= cchSize);
    } while (!buffer);
    *pszFileName = buffer;
    return TRUE;
}

int _tmain(int argc, TCHAR **argv)
{
    int i;
    MEMORY_BASIC_INFORMATION MemInfo;
    SIZE_T dwLength;
    LPCBYTE pStart, pEnd;
    LPCVOID pLastAllocBase = NULL;
    DWORD dwLastAllocProtect = 0;
    LPTSTR szFileName;
    BOOL bShowFree = FALSE;

    for (i = 1; i < argc; i++) {
        if (!_tcscmp(argv[1], _T("-f"))) {
            bShowFree = TRUE;
        }
    }

    for (pStart = 0; TRUE; pStart += MemInfo.RegionSize) {
        dwLength = VirtualQuery(pStart, &MemInfo, sizeof(MemInfo));
        if (!dwLength) {
            if (GetLastError() != ERROR_INVALID_PARAMETER) {
                print_winerr(_T("VirtualQuery"));
                return 1;
            }
            break;
        }
        assert(dwLength == sizeof(MemInfo));
        assert(MemInfo.BaseAddress == pStart);
        assert(MemInfo.RegionSize > 0);

        pEnd = pStart + MemInfo.RegionSize - 1;

        if (MemInfo.State == MEM_FREE) { /* 0x10000 */
            /* Free zone */
            if (!bShowFree) {
                continue;
            }
            _tprintf(
                _T("\n%16" PRIxPTR "..%16" PRIxPTR ": free\n"),
                (ULONG_PTR)pStart, (ULONG_PTR)pEnd);
            /* Show unexpected values */
            if (MemInfo.AllocationBase) {
                _tprintf(_T("... AllocationBase = %p\n"), MemInfo.AllocationBase);
            }
            if (MemInfo.AllocationProtect) {
                _tprintf(_T("... AllocationProtect = 0x%x\n"), MemInfo.AllocationProtect);
            }
            if (MemInfo.Protect != PAGE_NOACCESS) {
                _tprintf(_T("... Protect = 0x%x\n"), MemInfo.Protect);
            }
            if (MemInfo.Type) {
                _tprintf(_T("... Type = 0x%x\n"), MemInfo.Type);
            }
        } else {
            /* New allocation zone */
            if (MemInfo.AllocationBase == pStart) {
                _tprintf(
                    _T("\n%16" PRIxPTR ": allocation (%s)"),
                    (ULONG_PTR)MemInfo.AllocationBase,
                    describe_protect(MemInfo.AllocationProtect));
                if (MemInfo.Type == SEC_IMAGE &&
                    GetModuleFileNameWithAlloc(MemInfo.AllocationBase, &szFileName)) {
                    _tprintf(_T(" <%s>"), szFileName);
                    HeapFree(GetProcessHeap(), 0, szFileName);
                }
                _tprintf(_T("\n"));
                pLastAllocBase = MemInfo.AllocationBase;
                dwLastAllocProtect = MemInfo.AllocationProtect;
            } else if (MemInfo.AllocationBase != pLastAllocBase) {
                _ftprintf(
                    stderr,
                    _T("Error: allocation base changed to %p\n"),
                    MemInfo.AllocationBase);
            } else if (MemInfo.AllocationProtect != dwLastAllocProtect) {
                _ftprintf(
                    stderr,
                    _T("Error: allocation protection changed to %s\n"),
                    describe_protect(MemInfo.AllocationProtect));
            }
            _tprintf(
                _T("%16" PRIxPTR "..%16" PRIxPTR ": %s"),
                (ULONG_PTR)pStart, (ULONG_PTR)pEnd, describe_protect(MemInfo.Protect));

            if (MemInfo.State == MEM_COMMIT) { /* 0x1000 */
                _tprintf(_T(", commit"));
            } else if (MemInfo.State == MEM_RESERVE) { /* 0x2000 */
                _tprintf(_T(", reserve"));
            } else {
                _tprintf(_T(", unknown state 0x%x"), MemInfo.State);
            }

            if (MemInfo.Type == MEM_PRIVATE) { /* 0x20000 */
                _tprintf(_T(", private"));
            } else if (MemInfo.Type == MEM_MAPPED) { /* 0x40000 */
                _tprintf(_T(", mapped"));
            } else if (MemInfo.Type == MEM_IMAGE) { /* 0x1000000 */
                _tprintf(_T(", image"));
            } else {
                _tprintf(_T(", unknown type 0x%x"), MemInfo.Type);
            }
            _tprintf(_T("\n"));
        }
    }
    return 0;
}
