/**
 * Check the code which use Windows internal structures without using the
 * public API
 */
#include <assert.h>
#include <stdio.h>
#include <tchar.h>
#include "internal_structures.h"

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0 /* Only this value is used here */
} PROCESSINFOCLASS;

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

/**
 * Check that a given base name matches the full name
 */
static BOOL check_base_for_full(const UNICODE_STRING *base, const UNICODE_STRING *full)
{
    LPCWSTR szFullBase = full->Buffer;
    USHORT i, cchFullBase = full->Length / 2;
    WCHAR c;

    /* Extract the base name of full */
    for (i = 0; i < full->Length / 2; i++) {
        c = full->Buffer[i];
        if (!c) {
            cchFullBase -= full->Length / 2 - i;
            break;
        } else if (c == L'\\' || c == '/') {
            szFullBase = &full->Buffer[i + 1];
            cchFullBase = full->Length / 2 - i - 1;
        }
    }
    return (2 * cchFullBase <= base->Length) &&
        StringsCaseLenEqualsW(base->Buffer, szFullBase, cchFullBase) &&
        (2 * cchFullBase == base->Length || base->Buffer[cchFullBase] == 0);
}

int _tmain(void)
{
    NTSTATUS dwStatus;
    HMODULE hNtDll, hModule;
    HANDLE hProcess;
    pfnNtQueryInformationProcess _NtQueryInformationProcess;
    PROCESS_BASIC_INFORMATION pbi;
    OSVERSIONINFO ovi;
    const void *pTeb, *pTeb2;
    const PEB *pPeb;
    const LIST_ENTRY *ListHead, *ListEntry;
    const LDR_DATA_TABLE_ENTRY *CurEntry;
    const void *const *seh_entry;
    LPCVOID pModuleBase, pProcAddress, pProcAddress2;
    ULONG sizeNeeded;
    BOOL bRet, bHasKernelBase, bHasWow64CPU = FALSE;
    int i;

    /* Check internal structure offsets */
#if defined(__x86_64)
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, ProcessHeap) == 0x30);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, UserSharedInfoPtr) == 0x58);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, OSMajorVersion) == 0x118);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, ImageSubsystem) == 0x128);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, SessionId) == 0x2c0);
    BUILTTIME_ASSERT(FIELD_OFFSET(NT_TIB, Self) == 0x30);
    BUILTTIME_ASSERT(FIELD_OFFSET(TEB_internal, ProcessEnvironmentBlock) == 0x60);
#elif defined(__i386__)
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, ProcessHeap) == 0x18);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, UserSharedInfoPtr) == 0x2c);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, OSMajorVersion) == 0xa4);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, ImageSubsystem) == 0xb4);
    BUILTTIME_ASSERT(FIELD_OFFSET(PEB, SessionId) == 0x1d4);
    BUILTTIME_ASSERT(FIELD_OFFSET(NT_TIB, Self) == 0x18);
    BUILTTIME_ASSERT(FIELD_OFFSET(TEB_internal, ProcessEnvironmentBlock) == 0x30);
#else
#    warning Unsupported architecture
#endif

    /* Use public API */
    hProcess = GetCurrentProcess();
    hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    assert(hNtDll != NULL);
    _NtQueryInformationProcess =
        (pfnNtQueryInformationProcess) (void *)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    assert(_NtQueryInformationProcess != NULL);
    sizeNeeded = sizeof(pbi);
    dwStatus = _NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeNeeded, &sizeNeeded);
    assert(dwStatus == 0);

    /* gcc 12 reports a strange error when using NtCurrentTeb():
     * /usr/x86_64-w64-mingw32/sys-root/mingw/include/psdk_inc/intrin-impl.h:838:1:
     * error: array subscript 0 is outside array bounds of 'long long unsigned int[0]' [-Werror=array-bounds]
     *   838 | __buildreadseg(__readgsqword, unsigned __int64, "gs", "q")
     *       | ^~~~~~~~~~~~~~
     */
#if __GNUC__ >= 12 && __GNUC__ <= 13
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Warray-bounds"
#endif
    pTeb = NtCurrentTeb();
#if __GNUC__ >= 12 && __GNUC__ <= 13
#    pragma GCC diagnostic pop
#endif

    /* Directly use internal structures */
    pTeb2 = _NtCurrentTeb();
    if (pTeb != pTeb2) {
        printf("Invalid NtCurrentTeb implementation. Windows API gives %p and internal structures %p.\n",
               pTeb, pTeb2);
        return 1;
    }
    printf("Thread Environment block is at %p\n", pTeb);
    pPeb = _NtCurrentPeb();
    if (pPeb != pbi.PebBaseAddress) {
        printf("Unknown TEB format. PEB from TEB is %p but real one is %p.\n",
               pPeb, pbi.PebBaseAddress);
        return 1;
    }
    printf("Process Environment block is at %p\n", pPeb);

    /* Check ImageBase */
    hModule = GetModuleHandle(NULL);
    if (pPeb->ImageBaseAddress != (PVOID)hModule) {
        printf("Invalid ImageBaseAddress in PEB: %p, expected %p\n",
               pPeb->ImageBaseAddress, (PVOID)hModule);
        return 1;
    }
    printf("PEB ImageBaseAddress is %p\n", pPeb->ImageBaseAddress);

    /* Enumerate modules */
    printf("PEB Ldr is at %p\n", pPeb->Ldr);
    printf("In Memory Order list:\n");
    ListHead = &pPeb->Ldr->InMemoryOrderModuleList;
    for (ListEntry = ListHead->Flink; ListEntry != ListHead; ListEntry = ListEntry->Flink) {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        assert(&CurEntry->InMemoryOrderLinks == ListEntry);
        if (!check_base_for_full(&CurEntry->BaseDllName, &CurEntry->FullDllName)) {
            printf("Module %*S: base name mismatch with %*S\n",
                   CurEntry->FullDllName.Length / 2, CurEntry->FullDllName.Buffer,
                   CurEntry->BaseDllName.Length / 2, CurEntry->BaseDllName.Buffer);
            return 1;
        }
        /* Get Module base from standard API and compare the results */
        hModule = GetModuleHandleW(CurEntry->FullDllName.Buffer);
        if (hModule != CurEntry->DllBase) {
            printf("Module %*S: base address mismatch, hMod = %p, Ldr entry = %p\n",
                   CurEntry->FullDllName.Length / 2, CurEntry->FullDllName.Buffer,
                   hModule, CurEntry->DllBase);
            return 1;
        }
        printf("   %p: %*S\n", CurEntry->DllBase,
               CurEntry->FullDllName.Length / 2, CurEntry->FullDllName.Buffer);
    }

    /* Re-enumerate the modules, but in load order and with Base dll */
    printf("In Load Order list:\n");
    ListHead = &pPeb->Ldr->InLoadOrderModuleList;
    for (i = 0, ListEntry = ListHead->Flink; ListEntry != ListHead; i++, ListEntry = ListEntry->Flink) {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        assert(&CurEntry->InLoadOrderLinks == ListEntry);
        if (!check_base_for_full(&CurEntry->BaseDllName, &CurEntry->FullDllName)) {
            printf("Module %*S: base name mismatch with %*S\n",
                   CurEntry->FullDllName.Length / 2, CurEntry->FullDllName.Buffer,
                   CurEntry->BaseDllName.Length / 2, CurEntry->BaseDllName.Buffer);
            return 1;
        }
        hModule = GetModuleHandleW(CurEntry->FullDllName.Buffer);
        if (hModule != CurEntry->DllBase) {
            printf("Module %*S: base address mismatch, hMod = %p, Ldr entry = %p\n",
                   CurEntry->FullDllName.Length / 2, CurEntry->FullDllName.Buffer,
                   hModule, CurEntry->DllBase);
            return 1;
        }
        printf("   %p: %*S\n", CurEntry->DllBase,
               CurEntry->BaseDllName.Length / 2, CurEntry->BaseDllName.Buffer);

        /* Check expected order: base, ntdll, kernel32 */
        if (i == 0 && CurEntry->DllBase != (PVOID)GetModuleHandle(NULL)) {
            printf("Unexpected first module: not base\n");
            return 1;
        }
        if (i == 1 && !StringsCaseLenEqualsW(L"ntdll.dll",
                                             CurEntry->BaseDllName.Buffer,
                                             CurEntry->BaseDllName.Length / 2)) {
            printf("Unexpected second module: not ntdll.dll\n");
            return 1;
        }
        if (i == 2 && !StringsCaseLenEqualsW(L"KERNEL32.dll",
                                             CurEntry->BaseDllName.Buffer,
                                             CurEntry->BaseDllName.Length / 2)) {
            /* It may be C:\windows\system32\wow64cpu.dll */
            if (!StringsCaseLenEqualsW(L"wow64cpu.dll",
                                       CurEntry->BaseDllName.Buffer,
                                       CurEntry->BaseDllName.Length / 2)) {
                printf("Unexpected third module: not KERNEL32.dll\n");
                return 1;
            }
            bHasWow64CPU = TRUE;
        }
        /* If wow64cpu.dll was present, the next one is KERNEL32.dll */
        if (bHasWow64CPU && i == 3
            && !StringsCaseLenEqualsW(L"KERNEL32.dll",
                                      CurEntry->BaseDllName.Buffer,
                                      CurEntry->BaseDllName.Length / 2)) {
            printf("Unexpected fourth module: not KERNEL32.dll\n");
            return 1;
        }
    }

    /* Re-enumerate the modules, but in initialization order and with Base dll */
    bHasKernelBase = FALSE;
    printf("In Initialization Order list:\n");
    ListHead = &pPeb->Ldr->InInitializationOrderModuleList;
    for (i = 0, ListEntry = ListHead->Flink; ListEntry != ListHead; i++, ListEntry = ListEntry->Flink) {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        assert(&CurEntry->InInitializationOrderLinks == ListEntry);
        if (!check_base_for_full(&CurEntry->BaseDllName, &CurEntry->FullDllName)) {
            printf("Module %*S: base name mismatch with %*S\n",
                   CurEntry->FullDllName.Length / 2, CurEntry->FullDllName.Buffer,
                   CurEntry->BaseDllName.Length / 2, CurEntry->BaseDllName.Buffer);
            return 1;
        }
        hModule = GetModuleHandleW(CurEntry->FullDllName.Buffer);
        if (hModule != CurEntry->DllBase) {
            printf("Module %*S: base address mismatch, hMod = %p, Ldr entry = %p\n",
                   CurEntry->FullDllName.Length / 2, CurEntry->FullDllName.Buffer,
                   hModule, CurEntry->DllBase);
            return 1;
        }
        printf("   %p: %*S\n", CurEntry->DllBase,
               CurEntry->BaseDllName.Length / 2, CurEntry->BaseDllName.Buffer);

        /* Check expected order: ntdll then kernel32 or kernelbase, then kernel32 */
        if (i == 0 && !StringsCaseLenEqualsW(L"ntdll.dll",
                                             CurEntry->BaseDllName.Buffer,
                                             CurEntry->BaseDllName.Length / 2)) {
            printf("Unexpected first module: not ntdll.dll\n");
            return 1;
        }
        if (i == 1) {
            if (StringsCaseLenEqualsW(L"KERNELBASE.dll",
                                      CurEntry->BaseDllName.Buffer,
                                      CurEntry->BaseDllName.Length / 2)) {
                bHasKernelBase = TRUE;
            } else if (!StringsCaseLenEqualsW(L"KERNEL32.dll",
                                              CurEntry->BaseDllName.Buffer,
                                              CurEntry->BaseDllName.Length / 2)) {
                printf("Unexpected second module: not KERNEL32.dll nor KERNELBASE.dll\n");
                return 1;
            }
        }
        if (i == 2 && bHasKernelBase) {
            if (!StringsCaseLenEqualsW(L"KERNEL32.dll",
                                       CurEntry->BaseDllName.Buffer,
                                       CurEntry->BaseDllName.Length / 2)) {
                printf("Unexpected third module: not KERNEL32.dll\n");
                return 1;
            }
        }
    }

    /* Dump SEH, which may contain interesting addresses
     * Do not use EXCEPTION_REGISTRATION_RECORD as it is an internal non-standard
     * structure from MinGW excpt.h header.
     */
    seh_entry = (const void *const *)((const TEB_internal *)pTeb)->NtTib.ExceptionList;
    printf("SEH list:\n");
    while (seh_entry && seh_entry != (const void *const *)(-1)) {
        /* seh_entry[0] is the next entry and seh_entry[1] the handler function */
        printf("   %p: %p\n", seh_entry, seh_entry[1]);
        seh_entry = seh_entry[0];
    }

    /* Test some functions */
    pModuleBase = _GetModuleBase(L"ntdll.dll");
    if (pModuleBase != hNtDll) {
        printf("ntdll.dll base address mismatches, expected %p got %p\n",
               hNtDll, pModuleBase);
        return 1;
    }
    pProcAddress = _GetProcAddress(pModuleBase, "NtQueryInformationProcess");
    pProcAddress2 = (LPCVOID)_NtQueryInformationProcess;
    if (pProcAddress != pProcAddress2) {
        printf("NtQueryInformationProcess address mismatches, expected %p got %p\n",
               pProcAddress2, pProcAddress);
        return 1;
    }

    pModuleBase = _GetModuleBase(L"kernel32.dll");
    hModule = GetModuleHandleW(L"kernel32.dll");
    if (pModuleBase != hModule) {
        printf("kernel32.dll base address mismatches, expected %p got %p\n",
               hModule, pModuleBase);
        return 1;
    }
    pProcAddress = _GetProcAddress(pModuleBase, "ExitProcess");
    pProcAddress2 = GetProcAddress(hModule, "ExitProcess");
    if (pProcAddress != pProcAddress2) {
        printf("ExitProcess address mismatches, expected %p got %p\n",
               pProcAddress2, pProcAddress);
        return 1;
    }

    hModule = _LoadLibraryW(L"user32.dll");
    assert(hModule);
    pProcAddress = _GetProcAddress(hModule, "MessageBoxA");
    if (!pProcAddress) {
        printf("Unable to find MessageBoxA in user32.dll\n");
        return 1;
    }
    printf("MessageBoxA is at %p\n", pProcAddress);
    pProcAddress = _GetProcAddress(hModule, "MessageBoxW");
    if (!pProcAddress) {
        printf("Unable to find MessageBoxW in user32.dll\n");
        return 1;
    }
    printf("MessageBoxW is at %p\n", pProcAddress);
    bRet = _FreeLibrary(hModule);
    assert(bRet);

    FreeLibrary(hNtDll);

    /* Check other PEB fields */
    if (pPeb->ProcessHeap != (PVOID)GetProcessHeap()) {
        printf("Invalid ProcessHeap in PEB: %p, expected %p\n",
               pPeb->ProcessHeap, (PVOID)GetProcessHeap());
        return 1;
    }
    printf("Process heap is at %p\n", pPeb->ProcessHeap);

    printf("Number of processors: %lu\n", pPeb->NumberOfProcessors);

    printf("User32 shared info: %p\n", pPeb->UserSharedInfoPtr);

    /* Check OS version info */
    printf("OS version %lu.%lu build %u CSD %u\n",
           pPeb->OSMajorVersion, pPeb->OSMinorVersion, pPeb->OSBuildNumber,
           pPeb->OSCSDVersion);
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    if (!GetVersionEx(&ovi)) {
        printf("GetVersionEx failed with error %lu.\n", GetLastError());
        return 1;
    }
    if (ovi.dwMajorVersion != pPeb->OSMajorVersion ||
        ovi.dwMinorVersion != pPeb->OSMinorVersion ||
        ovi.dwBuildNumber != (DWORD)(pPeb->OSBuildNumber)) {
        printf("GetVersionEx returned a different version: %lu.%lu.%lu\n",
               ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber);
        /* This is not a fatal error, as it happens with Windows 10 Technical
         * Preview: PEB 10.0.9926, GetVersionEx 6.2.9200
         */
    }

    printf("Subsystem %lu version %lu.%lu\n",
           pPeb->ImageSubsystem, pPeb->ImageSubsystemMajorVersion,
           pPeb->ImageSubsystemMinorVersion);

    _ExitProcess(0);
    printf("Custom ExitProcess call failed\n");
    return 1;
}
