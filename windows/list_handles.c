/**
 * List the open handles that are available
 */
#include "common.h"
#include <inttypes.h>
#include <ntstatus.h>
#include <winternl.h>

/* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry.htm */
struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId; /* OwnerPid */
    USHORT CreatorBackTraceIndex;
    BYTE ObjectTypeIndex;
    BYTE HandleAttributes; /* HandleFlags */
    USHORT HandleValue;
    UINT_PTR ObjectPointer;
    ULONG GrantedAccess; /* AccessMask */
};
#if defined(__x86_64)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO) == 0x18);
#elif defined(__i386__)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO) == 0x10);
#else
#    warning Unsupported architecture
#endif

/* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm */
struct my_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[];
};
#if defined(__x86_64)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_INFORMATION) == 8);
#elif defined(__i386__)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_INFORMATION) == 4);
#else
#    warning Unsupported architecture
#endif

/* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry_ex.htm */
struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    UINT_PTR ObjectPointer;
    UINT_PTR UniqueProcessId;
    UINT_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};
#if defined(__x86_64)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) == 0x28);
#elif defined(__i386__)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) == 0x1c);
#else
#    warning Unsupported architecture
#endif

/* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm */
struct my_SYSTEM_HANDLE_INFORMATION_EX {
    UINT_PTR NumberOfHandles;
    UINT_PTR Reserved;
    struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[];
};
#if defined(__x86_64)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_INFORMATION_EX) == 0x10);
#elif defined(__i386__)
_STATIC_ASSERT(sizeof(struct my_SYSTEM_HANDLE_INFORMATION_EX) == 8);
#else
#    warning Unsupported architecture
#endif

/* static const SYSTEM_INFORMATION_CLASS SystemHandleInformation = 0x10; */
static const SYSTEM_INFORMATION_CLASS SystemExtendedHandleInformation = 0x40;

/**
 * Call NtQuerySystemInformation(SystemHandleInformation)
 *
 * NTSTATUS NTAPI NtQuerySystemInformation(
 *    SYSTEM_INFORMATION_CLASS SystemInformationClass,
 *    PVOID SystemInformation,
 *    ULONG SystemInformationLength,
 *    PULONG ReturnLength);
 */
static struct my_SYSTEM_HANDLE_INFORMATION *query_handles(void)
{
    NTSTATUS ntsResult;
    ULONG ulSize, ulRetSize, ulWinError, ulExpected;
    struct my_SYSTEM_HANDLE_INFORMATION *pHandleInfo = NULL;

    ulSize = 0;
    do {
        ulSize += 0x1000;
        if (pHandleInfo) {
            HeapFree(GetProcessHeap(), 0, pHandleInfo);
        }
        pHandleInfo = HeapAlloc(GetProcessHeap(), 0, ulSize);
        if (!pHandleInfo) {
            print_winerr(_T("HeapAlloc"));
            return NULL;
        }
        ulRetSize = 0;
        ntsResult = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, ulSize, &ulRetSize);
    } while (ntsResult == STATUS_INFO_LENGTH_MISMATCH);
    if (ntsResult != STATUS_SUCCESS) {
        ulWinError = RtlNtStatusToDosError(ntsResult);
        _ftprintf(stderr,
                  _T("NtQuerySystemInformation(SystemHandleInformation) returned error %#lx = %#lx\n"),
                  ntsResult, ulWinError);
        SetLastError(ulWinError);
        print_winerr(_T("NtQuerySystemInformation"));
        HeapFree(GetProcessHeap(), 0, pHandleInfo);
        return NULL;
    }
    /* Ensure the size matches */
    assert(ulRetSize > 0);
    assert(ulRetSize <= ulSize);
    ulExpected = (ULONG)(sizeof(struct my_SYSTEM_HANDLE_INFORMATION) +
                         pHandleInfo->NumberOfHandles * sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO));
    if (ulRetSize != ulExpected && pHandleInfo->NumberOfHandles == 0) {
        /* Old versions of Wine returned no handle, but the structure has room for one entry,
         * so update the expected size
         */
        ulExpected = (ULONG)(sizeof(struct my_SYSTEM_HANDLE_INFORMATION) + sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO));
    }
    if (ulRetSize != ulExpected) {
        _ftprintf(stderr,
                  _T("Error: NtQuerySystemInformation(SystemHandleInformation) returned %lu bytes, expected %lu = %lu + %lu * %lu\n"),
                  ulRetSize, ulExpected,
                  (ULONG)sizeof(struct my_SYSTEM_HANDLE_INFORMATION),
                  pHandleInfo->NumberOfHandles,
                  (ULONG)sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO));
        HeapFree(GetProcessHeap(), 0, pHandleInfo);
        return NULL;
    }
    return pHandleInfo;
}

/**
 * Call NtQuerySystemInformation(SystemExtendedHandleInformation)
 */
static struct my_SYSTEM_HANDLE_INFORMATION_EX *query_extended_handles(void)
{
    NTSTATUS ntsResult;
    ULONG ulSize, ulRetSize, ulWinError;
    struct my_SYSTEM_HANDLE_INFORMATION_EX *pHandleInfo = NULL;

    ulSize = 0;
    do {
        ulSize += 0x1000;
        if (pHandleInfo) {
            HeapFree(GetProcessHeap(), 0, pHandleInfo);
        }
        pHandleInfo = HeapAlloc(GetProcessHeap(), 0, ulSize);
        if (!pHandleInfo) {
            print_winerr(_T("HeapAlloc"));
            return NULL;
        }
        ulRetSize = 0;
        ntsResult = NtQuerySystemInformation(SystemExtendedHandleInformation, pHandleInfo, ulSize, &ulRetSize);
    } while (ntsResult == STATUS_INFO_LENGTH_MISMATCH);
    if (ntsResult != STATUS_SUCCESS) {
        ulWinError = RtlNtStatusToDosError(ntsResult);
        _ftprintf(stderr,
                  _T("NtQuerySystemInformation(SystemExtendedHandleInformation) returned error %#lx = %#lx\n"),
                  ntsResult, ulWinError);
        SetLastError(ulWinError);
        print_winerr(_T("NtQuerySystemInformation"));
        HeapFree(GetProcessHeap(), 0, pHandleInfo);
        return NULL;
    }
    /* Ensure the size matches */
    assert(ulRetSize > 0);
    assert(ulRetSize <= ulSize);
    assert(ulRetSize == (ULONG)(sizeof(struct my_SYSTEM_HANDLE_INFORMATION_EX) +
                                pHandleInfo->NumberOfHandles * sizeof(struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)));
    return pHandleInfo;
}

/**
 * Describe an access mask
 */
static void print_access_mask(ULONG ulAccessMask)
{
    assert(0x20000 == READ_CONTROL);
    assert(0x20003 == (READ_CONTROL | 3));
    assert(0x20006 == KEY_WRITE);
    assert(0x20008 == TOKEN_READ);
    assert(0x20019 == KEY_READ);
    assert(0x200e0 == TOKEN_WRITE);
    assert(0xf0000 == STANDARD_RIGHTS_REQUIRED);
    assert(0xf0001 == (STANDARD_RIGHTS_REQUIRED | 1));
    assert(0xf0007 == (STANDARD_RIGHTS_REQUIRED | 7));
    assert(0xf003f == KEY_ALL_ACCESS);
    assert(0xf00ff == TOKEN_ALL_ACCESS_P);
    assert(0xf01ff == TOKEN_ALL_ACCESS);
    assert(0x100000 == SYNCHRONIZE);
    assert(0x100020 == (SYNCHRONIZE | FILE_EXECUTE));
    assert(0x100020 == (SYNCHRONIZE | FILE_TRAVERSE));
    assert(0x120089 == FILE_GENERIC_READ);
    assert(0x1200a0 == FILE_GENERIC_EXECUTE);
    assert(0x120116 == FILE_GENERIC_WRITE);
    assert(0x12019f == (FILE_GENERIC_READ | FILE_GENERIC_WRITE));
    assert(0x1f0001 == (STANDARD_RIGHTS_ALL | 1));
    assert(0x1f0001 == MUTANT_ALL_ACCESS);
    assert(0x1f0003 == (STANDARD_RIGHTS_ALL | 3));
    assert(0x1f0003 == EVENT_ALL_ACCESS);
    assert(0x1f0003 == SEMAPHORE_ALL_ACCESS);
    assert(0x1f0003 == TIMER_ALL_ACCESS);
    assert(0x1f0003 == IO_COMPLETION_ALL_ACCESS);
    assert(0x1f001f == JOB_OBJECT_ALL_ACCESS);
    assert(0x1f01ff == FILE_ALL_ACCESS);
    assert(0x1f0fff == PROCESS_ALL_ACCESS || 0x1fffff == PROCESS_ALL_ACCESS);
    if (ulAccessMask == 0) {
        _tprintf(_T("NONE"));
    } else if (ulAccessMask < 0x1000) {
        _tprintf(_T("specific:%#lx"), ulAccessMask);
    } else if (ulAccessMask == 0x20000) {
        _tprintf(_T("rctl (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x20003) {
        _tprintf(_T("rctl|3 (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x20006) {
        _tprintf(_T("key_w (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x20008) {
        _tprintf(_T("token_r (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x20019) {
        _tprintf(_T("key_r (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x200e0) {
        _tprintf(_T("token_w (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0xf0000) {
        _tprintf(_T("std_req (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0xf0001) {
        _tprintf(_T("std_req|1 (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0xf0007) {
        _tprintf(_T("std_req|7 (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0xf003f) {
        _tprintf(_T("key_all (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0xf00ff) {
        _tprintf(_T("token_all_p (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0xf01ff) {
        _tprintf(_T("token_all (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x100000) {
        _tprintf(_T("sync (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x100020) {
        /* used for current directory in RtlSetCurrentDirectory_U:
         * https://source.winehq.org/git/wine.git/blob/4cdb7ec8291c171176fb390f4cef1f88409a982f:/dlls/ntdll/path.c#l1023
         */
        _tprintf(_T("sync|file_x (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x120089) {
        _tprintf(_T("file_gen_r (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x1200a0) {
        _tprintf(_T("file_gen_x (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x120116) {
        _tprintf(_T("file_gen_w (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x12019f) {
        _tprintf(_T("file_gen_rw (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x1f0001) {
        _tprintf(_T("std_all|1=mutant_all (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x1f0003) {
        _tprintf(_T("std_all|3=evt_all=sem_all=timer_all (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x1f001f) {
        _tprintf(_T("job_all (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x1f01ff) {
        _tprintf(_T("file_all (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x1f0fff) {
        _tprintf(_T("proc_all(old) (%#lx)"), ulAccessMask);
    } else if (ulAccessMask == 0x1fffff) {
        _tprintf(_T("proc_all (%#lx)"), ulAccessMask);
    } else {
        _tprintf(_T("UNKNOWN ACCESS %#lx !"), ulAccessMask);
    }
}

int _tmain(void)
{
    DWORD my_pid;
    UINT_PTR hCurrentProc, hCurrentThread, hStdin, hStdout, hStderr, hwndActive, hConsole, hCurDir;
    struct my_SYSTEM_HANDLE_INFORMATION *pHandleInfo;
    struct my_SYSTEM_HANDLE_INFORMATION_EX *pHandleInfoEx;
    ULONG idx;
    BYTE *pbUserProcParams;
    PEB *ProcessEnvironmentBlock;

    /* Retrieve well-known handles */
    my_pid = GetCurrentProcessId();
    hCurrentProc = (UINT_PTR)GetCurrentProcess();
    hCurrentThread = (UINT_PTR)GetCurrentThread();
    hStdin = (UINT_PTR)GetStdHandle(STD_INPUT_HANDLE);
    hStdout = (UINT_PTR)GetStdHandle(STD_OUTPUT_HANDLE);
    hStderr = (UINT_PTR)GetStdHandle(STD_ERROR_HANDLE);
    hwndActive = (UINT_PTR)GetActiveWindow();

    /* Retrieve the PEB (Process Environment Block), using the TEB (Thread Environment Block).
     * Unfortunately, MinGW-w64 did not include TEB::ProcessEnvironmentBlock before
     * version 6 and this commit from 2018-07-06:
     * https://github.com/mirror/mingw-w64/commit/cd320ea6aeb2c2352a3f9f4127fb8d15592ecb43
     * So use hard-coded offsets to retrieve the PEB.
     */
#if defined(__x86_64)
    ProcessEnvironmentBlock = *(PEB **)((BYTE *)NtCurrentTeb() + 0x60);
#elif defined(__i386__)
    ProcessEnvironmentBlock = *(PEB **)((BYTE *)NtCurrentTeb() + 0x30);
#else
#    warning Unsupported architecture
#endif
    pbUserProcParams = (BYTE *)ProcessEnvironmentBlock->ProcessParameters;

    /* ConsoleHandle is always at offset 0x10 of struct RTL_USER_PROCESS_PARAMETERS */
    hConsole = (UINT_PTR)*(HANDLE *)(pbUserProcParams + 0x10);

    /* CurrentDirectory.Handle is at an offset that depends on the system */
#if defined(__x86_64)
    hCurDir = (UINT_PTR)*(HANDLE *)(pbUserProcParams + 0x38 + 0x10);
#elif defined(__i386__)
    hCurDir = (UINT_PTR)*(HANDLE *)(pbUserProcParams + 0x24 + 8);
#else
#    warning Unsupported architecture
#endif

    _tprintf(_T("Known handles:\n"));
    _tprintf(_T("* Current process = %#" PRIxPTR "\n"), hCurrentProc);
    _tprintf(_T("* Current thread = %#" PRIxPTR "\n"), hCurrentThread);
    _tprintf(_T("* Standard input = %#" PRIxPTR "\n"), hStdin);
    _tprintf(_T("* Standard output = %#" PRIxPTR "\n"), hStdout);
    _tprintf(_T("* Standard error = %#" PRIxPTR "\n"), hStderr);
    _tprintf(_T("* Active window = %#" PRIxPTR "\n"), hwndActive);
    _tprintf(_T("* Console = %#" PRIxPTR "\n"), hConsole);
    _tprintf(_T("* Current directory = %#" PRIxPTR "\n"), hCurDir);
    _tprintf(_T("\n"));

    /* Query handle information */
    pHandleInfo = query_handles();
    if (!pHandleInfo)
        return 1;
    _tprintf(_T("NtQuerySystemInformation(SystemHandleInformation) returned %lu handles:\n"),
             pHandleInfo->NumberOfHandles);
    for (idx = 0; idx < pHandleInfo->NumberOfHandles; idx++) {
        struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO *entry = &pHandleInfo->Handles[idx];

        _tprintf(_T("  [%4lu] PID %u handle %#x"), idx, entry->UniqueProcessId, entry->HandleValue);
        if (entry->ObjectPointer) {
            _tprintf(_T(" objPtr %#" PRIxPTR), entry->ObjectPointer);
        }
        if (entry->ObjectTypeIndex) {
            _tprintf(_T(" objType %u"), entry->ObjectTypeIndex);
        }
        if (entry->HandleAttributes) {
            _tprintf(_T(" flags %#x"), entry->HandleAttributes);
        }
        _tprintf(_T(" access="));
        print_access_mask(entry->GrantedAccess);
        if (entry->CreatorBackTraceIndex) {
            _tprintf(_T(" Creator %u"), entry->CreatorBackTraceIndex);
        }

        if (entry->UniqueProcessId == my_pid) {
            if ((UINT_PTR)entry->HandleValue == (hCurrentProc & ~3)) {
                _tprintf(_T(" [PROCESS=%#" PRIxPTR "]"), hCurrentProc);
            }
            if ((UINT_PTR)entry->HandleValue == (hCurrentThread & ~3)) {
                _tprintf(_T(" [THREAD=%#" PRIxPTR "]"), hCurrentThread);
            }
            if ((UINT_PTR)entry->HandleValue == (hStdin & ~3)) {
                _tprintf(_T(" [STDIN=%#" PRIxPTR "]"), hStdin);
            }
            if ((UINT_PTR)entry->HandleValue == (hStdout & ~3)) {
                _tprintf(_T(" [STDOUT=%#" PRIxPTR "]"), hStdout);
            }
            if ((UINT_PTR)entry->HandleValue == (hStderr & ~3)) {
                _tprintf(_T(" [STDERR=%#" PRIxPTR "]"), hStderr);
            }
            if ((UINT_PTR)entry->HandleValue == (hwndActive & ~3)) {
                _tprintf(_T(" [Active HWND=%#" PRIxPTR "]"), hwndActive);
            }
            if ((UINT_PTR)entry->HandleValue == (hConsole & ~3)) {
                _tprintf(_T(" [CONSOLE=%#" PRIxPTR "]"), hConsole);
            }
            if ((UINT_PTR)entry->HandleValue == (hCurDir & ~3)) {
                _tprintf(_T(" [CURDIR=%#" PRIxPTR "]"), hCurDir);
            }
        }
        _tprintf(_T("\n"));
    }
    HeapFree(GetProcessHeap(), 0, pHandleInfo);
    _tprintf(_T("\n"));

    /* Query extended handle information */
    pHandleInfoEx = query_extended_handles();
    if (!pHandleInfoEx) {
        _tprintf(_T("Querying extended handles is not supported on this system\n"));
    } else {
        _tprintf(_T("NtQuerySystemInformation(SystemExtendedHandleInformation) returned %" PRIuPTR " extended handles\n"),
                 pHandleInfoEx->NumberOfHandles);
        for (idx = 0; idx < pHandleInfoEx->NumberOfHandles; idx++) {
            struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *entry = &pHandleInfoEx->Handles[idx];

            _tprintf(_T("  [%4lu] PID %" PRIuPTR " handle %#" PRIxPTR),
                     idx, entry->UniqueProcessId, entry->HandleValue);
            if (entry->ObjectPointer) {
                _tprintf(_T(" objPtr %#" PRIxPTR), entry->ObjectPointer);
            }
            if (entry->ObjectTypeIndex) {
                _tprintf(_T(" objType %u"), entry->ObjectTypeIndex);
            }
            if (entry->HandleAttributes) {
                _tprintf(_T(" flags %#lx"), entry->HandleAttributes);
            }
            if (entry->Reserved) {
                _tprintf(_T(" reserved %#lx"), entry->Reserved);
            }
            _tprintf(_T(" access="));
            print_access_mask(entry->GrantedAccess);
            if (entry->CreatorBackTraceIndex) {
                _tprintf(_T(" Creator %u"), entry->CreatorBackTraceIndex);
            }

            if (entry->UniqueProcessId == my_pid) {
                if ((UINT_PTR)entry->HandleValue == (hCurrentProc & ~3)) {
                    _tprintf(_T(" [PROCESS=%#" PRIxPTR "]"), hCurrentProc);
                }
                if ((UINT_PTR)entry->HandleValue == (hCurrentThread & ~3)) {
                    _tprintf(_T(" [THREAD=%#" PRIxPTR "]"), hCurrentThread);
                }
                if ((UINT_PTR)entry->HandleValue == (hStdin & ~3)) {
                    _tprintf(_T(" [STDIN=%#" PRIxPTR "]"), hStdin);
                }
                if ((UINT_PTR)entry->HandleValue == (hStdout & ~3)) {
                    _tprintf(_T(" [STDOUT=%#" PRIxPTR "]"), hStdout);
                }
                if ((UINT_PTR)entry->HandleValue == (hStderr & ~3)) {
                    _tprintf(_T(" [STDERR=%#" PRIxPTR "]"), hStderr);
                }
                if ((UINT_PTR)entry->HandleValue == (hwndActive & ~3)) {
                    _tprintf(_T(" [Active HWND=%#" PRIxPTR "]"), hwndActive);
                }
                if ((UINT_PTR)entry->HandleValue == (hConsole & ~3)) {
                    _tprintf(_T(" [CONSOLE=%#" PRIxPTR "]"), hConsole);
                }
                if ((UINT_PTR)entry->HandleValue == (hCurDir & ~3)) {
                    _tprintf(_T(" [CURDIR=%#" PRIxPTR "]"), hCurDir);
                }
            }
            _tprintf(_T("\n"));
        }
        HeapFree(GetProcessHeap(), 0, pHandleInfoEx);
    }
    return 0;
}
