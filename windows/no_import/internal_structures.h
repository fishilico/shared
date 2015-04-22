/**
 * Windows internal structure
 */
#ifndef INTERNAL_STRUCTURES_H
#define INTERNAL_STRUCTURES_H

#include <windows.h>

/* Define a custom static assert to prevent issues with duplicate externs.
 * This static assert is to be used inside functions.
 */
#define BUILTTIME_ASSERT(cond) ((void)sizeof(char[1 - 2*!(cond)]))

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
#    define __UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
#endif

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2;
    LIST_ENTRY InLoadOrderModuleList; /* Undocumented */
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList; /* Undocumented */
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks; /* Undocumented */
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks; /* Undocumented */
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved1;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName; /* Undocumented */
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/* Offsets are written for 32- and 64-bit systems.
 * For comparaison with several Windows versions, see:
 * http://blog.rewolf.pl/blog/?p=573 Evolution of Process Environment Block
 */
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged; /* 0x002 0x002 */
    BYTE Reserved2[1];
    PVOID Reserved3;
    PVOID ImageBaseAddress; /* 0x008 0x010 */
    PPEB_LDR_DATA Ldr; /* 0x00C 0x018 */
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters; /* 0x010 0x020 */
    PVOID SubSystemData; /* 0x014 0x028 */
    PVOID ProcessHeap; /* Ox018 0x030 */
    BYTE Reserved4[16];
    PVOID Reserved5[14];
    DWORD NumberOfProcessors; /* 0x064 0x0b8 */
    DWORD NtGlobalFlag; /* 0x068 0x0bc */
    BYTE Reserved6[24];
    PVOID Reserved7[8];
    DWORD OSMajorVersion; /* 0x0a4 0x118 */
    DWORD OSMinorVersion; /* 0x0a8 0x11c */
    WORD OSBuildNumber; /* 0x0ac 0x120 */
    WORD OSCSDVersion; /* 0x0ae 0x122 */
    DWORD OSPlatformId; /* 0x0b0 0x124 */
    DWORD ImageSubsystem; /* 0x0b4 0x128 */
    DWORD ImageSubsystemMajorVersion; /* 0x0b8 0x12c */
    DWORD ImageSubsystemMinorVersion; /* 0x0bc 0x130 */
    BYTE Reserved8[156];
    PVOID Reserved9[30];
    ULONG SessionId; /* 0x1d4 0x2c0 */
} PEB, *PPEB;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* NT_TIB conflicts with a definition in winnt.h header from MinGW */
typedef struct _NT_TIB_redef {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        DWORD Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB_redef, *PNT_TIB_redef;
#define NT_TIB NT_TIB_redef

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
 * Get the linear address of the Thread Environment Block
 */
static const TEB_internal* _NtCurrentTeb(VOID)
{
    PTEB_internal pTeb;
#if defined(__x86_64)
    BUILTTIME_ASSERT(FIELD_OFFSET(NT_TIB, Self) == 0x30);
    __asm__ volatile ("movq %%gs:48, %0"
        : "=r" (pTeb));
#elif defined(__i386__)
    BUILTTIME_ASSERT(FIELD_OFFSET(NT_TIB, Self) == 0x18);
    __asm__ volatile ("movl %%fs:24, %0"
        : "=r" (pTeb));
#else
    /* Use Windows API headers */
    pTeb = (PTEB_internal)NtCurrentTeb();
#endif
    return pTeb;
}

/**
 * Get current Process Environment Block
 */
static const PEB* _NtCurrentPeb(VOID)
{
    PPEB pPeb;
#if defined(__x86_64)
    BUILTTIME_ASSERT(FIELD_OFFSET(TEB_internal, ProcessEnvironmentBlock) == 0x60);
    __asm__ volatile ("movq %%gs:96, %0"
        : "=r" (pPeb));
#elif defined(__i386__)
    BUILTTIME_ASSERT(FIELD_OFFSET(TEB_internal, ProcessEnvironmentBlock) == 0x30);
    __asm__ volatile ("movl %%fs:48, %0"
        : "=r" (pPeb));
#else
    const TEB_internal *pTeb = _NtCurrentTeb();
    if (!pTeb) {
        return NULL;
    }
    pPeb = pTeb->ProcessEnvironmentBlock;
#endif
    return pPeb;
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
        modnamelen = CurEntry->FullDllName.Length / 2;
        for (i = 0; i < CurEntry->FullDllName.Length / 2; i++) {
            WCHAR c = CurEntry->FullDllName.Buffer[i];
            if (!c) {
                modnamelen -= CurEntry->FullDllName.Length / 2 - i;
                break;
            } else if (c == L'\\' || c == '/') {
                szCurModuleName = &CurEntry->FullDllName.Buffer[i + 1];
                modnamelen = CurEntry->FullDllName.Length / 2 - i - 1;
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
    const BYTE *pbModuleBase = (PBYTE)pModuleBase;
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
