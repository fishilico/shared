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
    BOOL bRet;

    /* Use public API */
    hProcess = GetCurrentProcess();
    hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    assert(hNtDll != NULL);
    _NtQueryInformationProcess = \
        (pfnNtQueryInformationProcess) GetProcAddress(hNtDll, "NtQueryInformationProcess");
    assert(_NtQueryInformationProcess != NULL);
    sizeNeeded = sizeof(pbi);
    dwStatus = _NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeNeeded, &sizeNeeded);
    assert(dwStatus == 0);

    /* Directly use internal structures */
    pTeb = NtCurrentTeb();
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
    ListHead = &pPeb->Ldr->InMemoryOrderModuleList;
    ListEntry = ListHead->Flink;
    while (ListEntry != ListHead) {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        assert(&CurEntry->InMemoryOrderLinks == ListEntry);
        /* Get Module base from standard API and compare the results */
        hModule = GetModuleHandleW(CurEntry->FullDllName.Buffer);
        if (hModule != CurEntry->DllBase) {
            printf("Module %S: base address mismatch, hMod = %p, Ldr entry = %p\n",
                   CurEntry->FullDllName.Buffer, hModule, CurEntry->DllBase);
            return 1;
        }
        printf("   %p: %S\n", CurEntry->DllBase, CurEntry->FullDllName.Buffer);
        ListEntry = ListEntry->Flink;
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
        return 1;
    }

    printf("Subsystem %lu version %lu.%lu\n",
           pPeb->ImageSubsystem, pPeb->ImageSubsystemMajorVersion,
           pPeb->ImageSubsystemMinorVersion);

    _ExitProcess(0);
    printf("Custom ExitProcess call failed\n");
    return 1;
}
