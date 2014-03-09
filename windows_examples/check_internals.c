/**
 * Check the code which use Windows internal structures without using the
 * public API
 */
#include <assert.h>
#include <stdio.h>
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

int main()
{
    NTSTATUS dwStatus;
    HMODULE hNtDll, hModule;
    HANDLE hProcess;
    pfnNtQueryInformationProcess _NtQueryInformationProcess;
    PROCESS_BASIC_INFORMATION pbi;
    const void *pTeb;
    const PEB *pPeb;
    const LIST_ENTRY *ListHead, *ListEntry;
    const LDR_DATA_TABLE_ENTRY *CurEntry;
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
    printf("Thread Environment block is at %p\n", pTeb);
    pPeb = _NtCurrentPeb();
    if (pPeb != pbi.PebBaseAddress) {
        printf("Unknown TEB format. PEB from TEB is %p but real one is %p.\n",
            pPeb, pbi.PebBaseAddress);
        return 1;
    }
    printf("Process Environment block is at %p\n", pPeb);
    printf("PEB Ldr is at at %p\n", pPeb->Ldr);

    /* Enumerate modules */
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
    bRet = _FreeLibrary(hModule);
    assert(bRet);

    FreeLibrary(hNtDll);
    _ExitProcess(0);
    printf("Custom ExitProcess call failed\n");
    return 1;
}
