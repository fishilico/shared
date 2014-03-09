/**
 * Windows internal structure
 */
#ifndef INTERNAL_STRUCTURES_H
#define INTERNAL_STRUCTURES_H

#include <windows.h>

/**
 * winnt.h provides NtCurrentTeb to retrieve the Thread Environment Block, which
 * lies in special locations (in fs segment on 32-bits x86, gs on x86_64, and at
 * a fixed address on ARM)
 *
 * reactos/include/ndk/peb_teb.h gives the offset of the Process Environment
 * Block address in the TEB structure
 */
typedef LONG NTSTATUS, *PNTSTATUS;

#ifndef __UNICODE_STRING_DEFINED
#define __UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
#endif

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    PVOID Reserved6;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[53];
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

#pragma pack(push,1)
typedef struct _TEB_internal {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
} TEB_internal, *PTEB_internal;
#pragma pack(pop)

static BOOL StringsEqualsA(LPCSTR str1, LPCSTR str2)
{
    while (*str1 && *str1 == *str2) {
        str1++;
        str2++;
    }
    return *str1 == *str2;
}

static WCHAR UpperWChar(WCHAR c)
{
    if (c >= L'a' && c <= L'z') {
        return c - L'a' + L'A';
    }
    return c;
}

static BOOL StringsCaseLenEqualsW(LPCWSTR str1, LPCWSTR str2, ULONG cbLen)
{
    while (*str1 && UpperWChar(*str1) == UpperWChar(*str2) && cbLen > 0) {
        str1++;
        str2++;
        cbLen--;
    }
    return cbLen == 0 || (*str1 == 0 && *str2 == 0);
}

/**
 * Get current Process Environment Block
 */
static PPEB _NtCurrentPeb(VOID)
{
    const TEB_internal *pTeb = (PTEB_internal)NtCurrentTeb();
    if (!pTeb) {
        return NULL;
    }
    return pTeb->ProcessEnvironmentBlock;
}

/**
 * Find a module using the Processus Environment Block
 */
static LPCVOID _GetModuleBase(LPCWSTR szModuleName)
{
    const PEB *pPeb;
    const LIST_ENTRY *ListHead, *ListEntry;
    const LDR_DATA_TABLE_ENTRY *CurEntry;
    LPCWSTR szCurModuleName;
    USHORT i, modnamelen;

    pPeb = _NtCurrentPeb();
    if (!pPeb) {
        return NULL;
    }

    /* Code from reactos/dll/ntdll/ldr/ldrutils.c, function LdrpCheckForLoadedDll */
    ListHead = &pPeb->Ldr->InMemoryOrderModuleList;
    ListEntry = ListHead->Flink;
    while (ListEntry != ListHead) {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        ListEntry = ListEntry->Flink;
        /* Find the last directory separator of the full DLL name */
        szCurModuleName = CurEntry->FullDllName.Buffer;
        modnamelen = CurEntry->FullDllName.Length;
        for (i = 0; i < CurEntry->FullDllName.Length; i++) {
            WCHAR c = CurEntry->FullDllName.Buffer[i];
            if (!c) {
                modnamelen -= CurEntry->FullDllName.Length - i;
                break;
            } else if (c == L'\\' || c == '/') {
                szCurModuleName = &CurEntry->FullDllName.Buffer[i + 1];
                modnamelen = CurEntry->FullDllName.Length - i - 1;
            }
        }
        if (StringsCaseLenEqualsW(szCurModuleName, szModuleName, modnamelen) &&
            szModuleName[modnamelen] == L'\0') {
            return CurEntry->DllBase;
        }
    }
    return NULL;
}

/**
 * Find a function in a module, given its name
 */
static LPCVOID _GetProcAddress(LPCVOID pModuleBase, LPCSTR szFunctionName)
{
    const BYTE *pbModuleBase = (PBYTE) pModuleBase;
    const IMAGE_DOS_HEADER *pDOSHeader;
    const IMAGE_NT_HEADERS *pNTHeader;
    const IMAGE_DATA_DIRECTORY *pExportDataDir;
    const IMAGE_EXPORT_DIRECTORY *pExportDir;
    const ULONG *pFunctions;
    const SHORT *pOrdinals;
    const ULONG *pNames;
    ULONG i, ord, max_name, max_func;

    if (!pModuleBase || !szFunctionName) {
        return NULL;
    }
    /* Read the PE header (DOS, NT and Optional headers) */
    pDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    pNTHeader = (PIMAGE_NT_HEADERS)(pbModuleBase + pDOSHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    if (pNTHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        pNTHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return NULL;
    }
    pExportDataDir = (PIMAGE_DATA_DIRECTORY) pNTHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;

    if (pExportDataDir->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return NULL;
    }

    /* Read the export directory */
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pbModuleBase + pExportDataDir->VirtualAddress);
    pFunctions = (PULONG)(pbModuleBase + pExportDir->AddressOfFunctions);
    pOrdinals = (PSHORT)(pbModuleBase + pExportDir->AddressOfNameOrdinals);
    pNames = (PULONG)(pbModuleBase + pExportDir->AddressOfNames);
    max_name = pExportDir->NumberOfNames;
    max_func = pExportDir->NumberOfFunctions;
    for (i = 0; i < max_name; i++) {
        ord = pOrdinals[i];
        if (ord >= max_func) {
            return NULL;
        }
        if (StringsEqualsA((LPCSTR)(pbModuleBase + pNames[i]), szFunctionName)) {
            return (PVOID)(pbModuleBase + pFunctions[ord]);
        }
    }
    return NULL;
}

static LPCVOID _GetKernel32ProcAddress(LPCSTR szFunctionName)
{
    static LPCVOID pModuleBase = NULL;
    if (!pModuleBase) {
        pModuleBase = _GetModuleBase(L"kernel32.dll");
        if (!pModuleBase) {
            return NULL;
        }
    }
    return _GetProcAddress(pModuleBase, szFunctionName);
}

static VOID _ExitProcess(UINT uExitCode)
{
    VOID (WINAPI *pfnExitProcess)(IN UINT uExitCode);
    pfnExitProcess = _GetKernel32ProcAddress("ExitProcess");
    if (!pfnExitProcess) {
        return;
    }
    pfnExitProcess(uExitCode);
}

static HMODULE _LoadLibraryW(LPCWSTR lpFileName)
{
    HMODULE (WINAPI *pfnLoadLibraryW)(IN LPCWSTR lpFileName);
    pfnLoadLibraryW = _GetKernel32ProcAddress("LoadLibraryW");
    return pfnLoadLibraryW ? pfnLoadLibraryW(lpFileName) : NULL;
}

static BOOL _FreeLibrary(HMODULE hModule)
{
    BOOL (WINAPI *pfnFreeLibrary)(IN HMODULE hModule);
    pfnFreeLibrary = _GetKernel32ProcAddress("FreeLibrary");
    return pfnFreeLibrary ? pfnFreeLibrary(hModule) : FALSE;
}

#endif /* INTERNAL_STRUCTURES_H */
