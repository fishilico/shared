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

/**
 * Wrap GetMappedFileName to allocate memory
 */
static BOOL GetMappedFileNameWithAlloc(LPVOID lpAddr, LPTSTR *pszFileName)
{
    LPTSTR buffer = NULL;
    DWORD cchSize = 1024, cchRet;

    assert(lpAddr && pszFileName);
    do {
        buffer = HeapAlloc(GetProcessHeap(), 0, cchSize * sizeof(TCHAR));
        if (!buffer) {
            print_winerr(_T("HeapAlloc"));
            return FALSE;
        }
        cchRet = GetMappedFileName(GetCurrentProcess(), lpAddr, buffer, cchSize);
        if (!cchRet) {
            print_winerr(_T("GetMappedFileName"));
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

/**
 * Get a pointer in the stack
 */
static LPCVOID get_stack_pointer(void)
{
    LPCVOID pStack;
#if defined(__x86_64)
    __asm__ volatile ("movq %%rsp, %0" : "=r" (pStack));
#elif defined(__i386__)
    __asm__ volatile ("movl %%esp, %0" : "=r" (pStack));
#else
#    warning "get_stack_pointer not yet implemented for this architecture"
    pStack = NULL;
#endif
#ifdef _NT_TIB_DEFINED
    /* Check with TEB */
    {
        const NT_TIB *pTib = (PNT_TIB)NtCurrentTeb();
        if (pTib->StackLimit < pTib->StackBase) {
            /* Stack grows down from base to limit */
            if (pStack < pTib->StackLimit || pStack > pTib->StackBase) {
                _ftprintf(
                    stderr,
                    _T("Warning: stack pointer %p not in stack limits %p..%p\n"),
                    pStack, pTib->StackLimit, pTib->StackBase);
                pStack = pTib->StackLimit;
            }
        } else {
            /* Stack grows up from base to limit */
            if (pStack < pTib->StackBase || pStack > pTib->StackLimit) {
                _ftprintf(
                    stderr,
                    _T("Warning: stack pointer %p not in stack limits %p..%p\n"),
                    pStack, pTib->StackBase, pTib->StackLimit);
                pStack = pTib->StackBase;
            }
        }
    }
#endif
    return pStack;
}

/**
 * Get the Process Environment Block, with the "documented way"
 * Use NtQueryInformationProcess, dynamically loaded from ntdll
 */
typedef DWORD (WINAPI * pfnNtQueryInformationProcess_t) (
    HANDLE ProcessHandle,
    int ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);
static LPCVOID get_peb_query_info_proc(void)
{
    HMODULE hModNtdll;
    pfnNtQueryInformationProcess_t pfnNtQueryInformationProcess;
    DWORD status;
    ULONG length = 0;
    /* Use PROCESS_BASIC_INFORMATION without actually using it */
    struct {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } ProcBasicInfo;

    hModNtdll = LoadLibrary(_T("ntdll.dll"));
    if (!hModNtdll) {
        print_winerr(_T("LoadLibrary(ntdll)"));
        return NULL;
    }

    pfnNtQueryInformationProcess = (pfnNtQueryInformationProcess_t)GetProcAddress(
        hModNtdll, "NtQueryInformationProcess");
    if (!pfnNtQueryInformationProcess) {
        print_winerr(_T("GetProcAddress(ntdll, NtQueryInformationProcess)"));
        FreeLibrary(hModNtdll);
        return NULL;
    }

    /* Query ProcessBasicInformation = 0 */
    status = (*pfnNtQueryInformationProcess)(GetCurrentProcess(), 0, &ProcBasicInfo, sizeof(ProcBasicInfo), &length);
    FreeLibrary(hModNtdll);
    if (status) {
        _ftprintf(stderr, _T("NtQueryInformationProcess: error %lu\n"), status);
        return NULL;
    }
    return ProcBasicInfo.PebBaseAddress;
}

/**
 * Get the Process Environment Block from the Thread Environment Block
 */
static LPCVOID get_peb_from_teb(void)
{
    LPCVOID pPeb;
#if defined(__x86_64)
     __asm__ volatile ("movq %%gs:96, %0" : "=r" (pPeb));
#elif defined(__i386__)
    __asm__ volatile ("movl %%fs:48, %0" : "=r" (pPeb));
#else
#    warning "get_peb_from_teb not yet implemented for this architecture"
    pPeb = NULL;
#endif
    return pPeb;
}

/**
 * Get the Process Environment Block using every available method
 */
static LPCVOID get_peb(void)
{
    LPCVOID pPebInfoProc, pPebTeb;

    pPebInfoProc = get_peb_query_info_proc();
    pPebTeb = get_peb_from_teb();
    if (pPebInfoProc) {
        if (pPebTeb && pPebTeb != pPebInfoProc) {
            _ftprintf(
                stderr,
                _T("Warning: PEB = %p from process info and %p from TEB\n"),
                pPebInfoProc, pPebTeb);
        }
        return pPebInfoProc;
    }
    return pPebTeb;
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
    LPCVOID pStack, pTeb, pPeb;
    LPVOID pHeap;

    /* Gather stack, heap, Thread Environment Block and Process Environment Block */
    pStack = get_stack_pointer();
    pHeap = HeapAlloc(GetProcessHeap(), 0, 1);
    pTeb = NtCurrentTeb();
    pPeb = get_peb();

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
                if (MemInfo.Type == MEM_IMAGE &&
                    GetModuleFileNameWithAlloc(MemInfo.AllocationBase, &szFileName)) {
                    /* Show associated file for image allocations */
                    _tprintf(_T(" <%s>"), szFileName);
                    HeapFree(GetProcessHeap(), 0, szFileName);
                } else if (MemInfo.Type == MEM_MAPPED &&
                    GetMappedFileNameWithAlloc(MemInfo.AllocationBase, &szFileName)) {
                    /* Show associated file for mapped allocations */
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

            if ((LPCVOID)pStart <= pStack && pStack <= (LPCVOID)pEnd) {
                _tprintf(_T(" [stack]"));
            }
            if ((LPCVOID)pStart <= pHeap && pHeap <= (LPCVOID)pEnd) {
                _tprintf(_T(" [heap]"));
            }
            if ((LPCVOID)pStart <= pTeb && pTeb <= (LPCVOID)pEnd) {
                _tprintf(_T(" [TEB@%" PRIxPTR "]"), (ULONG_PTR)pTeb);
            }
            if ((LPCVOID)pStart <= pPeb && pPeb <= (LPCVOID)pEnd) {
                _tprintf(_T(" [PEB@%" PRIxPTR "]"), (ULONG_PTR)pPeb);
            }

            _tprintf(_T("\n"));
        }
    }
    if (pHeap) {
        HeapFree(GetProcessHeap(), 0, pHeap);
    }
    return 0;
}
