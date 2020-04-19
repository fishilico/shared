/**
 * Windows internal structure
 *
 * Online documentation:
 * * https://github.com/maldevel/Peteb/blob/master/src/SystemTypes.h
 * * https://ntdiff.github.io/
 * * https://github.com/wine-mirror/wine/blob/master/include/winternl.h
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
    USHORT Length; /* offset 0 */
    USHORT MaximumLength; /* offset 2 */
    PWSTR Buffer; /* offset 4 on 32-bit, 8 on 64-bit */
} UNICODE_STRING;
#endif

typedef struct _PEB_LDR_DATA {
    DWORD Length; /* offset 0x00 */
    UCHAR Initialized; /* offset 0x04 */
    BYTE Reserved1[3];
    PVOID SsHandle; /* offset 0x08 */
    LIST_ENTRY InLoadOrderModuleList; /* Undocumented, offset 0x0c or 0x10 */
    LIST_ENTRY InMemoryOrderModuleList; /* offset 0x14 or 0x20 */
    LIST_ENTRY InInitializationOrderModuleList; /* Undocumented, offset 0x1c or 0x30 */
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks; /* Undocumented, offset 0 */
    LIST_ENTRY InMemoryOrderLinks; /* offset 0x08 or 0x10 */
    LIST_ENTRY InInitializationOrderLinks; /* Undocumented, offset 0x10 or 0x20 */
    PVOID DllBase; /* offset 0x18 or 0x30 */
    PVOID EntryPoint; /* offset 0x1c or 0x38 */
    PVOID Reserved1;
    UNICODE_STRING FullDllName; /* offset 0x20 or 0x40 */
    UNICODE_STRING BaseDllName; /* Undocumented, offset 0x28 or 0x50 */
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _CURDIR {
    UNICODE_STRING DosPath; /* offset 0 */
    HANDLE Handle; /* offset 8 or 0x10 */
} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    DWORD MaximumLength; /* 0x000 0x000 */
    DWORD Length; /* 0x004 0x004 */
    DWORD Flags; /* 0x008 0x008 */
    DWORD DebugFlags; /* 0x00c 0x00c */
    HANDLE ConsoleHandle; /* 0x010 0x010 */
    DWORD onsoleFlags; /* 0x014 0x018 */
    HANDLE StandardInput; /* 0x018 0x020 */
    HANDLE StandardOutput; /* 0x01c 0x028 */
    HANDLE StandardError; /* 0x020 0x030 */
    CURDIR CurrentDirectory; /* 0x024 0x038 */
    UNICODE_STRING DllPath; /* 0x030 0x050 */
    UNICODE_STRING ImagePathName; /* 0x038 0x060 */
    UNICODE_STRING CommandLine; /* 0x040 0x070 */
    PVOID Environment; /* 0x048 0x080 */
    DWORD StartingX; /* 0x04c 0x088 */
    DWORD StartingY; /* 0x050 0x08c */
    DWORD CountX; /* 0x054 0x090 */
    DWORD CountY; /* 0x058 0x094 */
    DWORD CountCharsX; /* 0x05c 0x098 */
    DWORD CountCharsY; /* 0x060 0x09c */
    DWORD FillAttribute; /* 0x064 0x0a0 */
    DWORD WindowFlags; /* 0x068 0x0a4 */
    DWORD ShowWindowFlags; /* 0x06c 0x0a8 */
    UNICODE_STRING WindowTitle; /* 0x070 0x0b0 */
    UNICODE_STRING DesktopInfo; /* 0x078 0x0c0 */
    UNICODE_STRING ShellInfo; /* 0x080 0x0d0 */
    UNICODE_STRING RuntimeData; /* 0x088 0x0e0 */
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/* Offsets are written for 32- and 64-bit systems.
 * For comparison with several Windows versions, see:
 * http://blog.rewolf.pl/blog/?p=573 Evolution of Process Environment Block
 * https://ntdiff.github.io/#versionLeft=WinVista_SP1%2Fx86%2FSystem32&filenameLeft=ntoskrnl.exe&typeLeft=Standalone%2F_PEB&versionRight=Win10_20H1_19037%2Fx86%2FSystem32&filenameRight=ntoskrnl.exe&typeRight=Standalone%2F_PEB
 */
typedef struct _PEB {
    BYTE InheritedAddressSpace; /* 0x000 0x000 */
    BYTE ReadImageFileExecOptions; /* 0x001 0x001 */
    BYTE BeingDebugged; /* 0x002 0x002 */
    BYTE BitField; /* 0x003 0x003 */
    PVOID Mutant; /* 0x004 0x008 */
    PVOID ImageBaseAddress; /* 0x008 0x010 */
    PPEB_LDR_DATA Ldr; /* 0x00c 0x018 */
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters; /* 0x010 0x020 */
    PVOID SubSystemData; /* 0x014 0x028 */
    PVOID ProcessHeap; /* 0x018 0x030 */
    void *FastPebLock; /* 0x01c 0x038 */
    void *AtlThunkSListPtr; /* 0x020 0x040 */
    void *IFEOKey; /* 0x024 0x048 */
    DWORD CrossProcessFlags; /* 0x028 0x050 */
    PVOID UserSharedInfoPtr; /* 0x02c 0x058 */
    DWORD SystemReserved; /* 0x030 0x060 */
    DWORD Reserved1; /* 0x034 0x064 */
    PVOID Reserved2; /* 0x038 0x068 */
    DWORD TlsExpansionCounter; /* 0x03c 0x070 */
    PVOID TlsBitmap; /* 0x040 0x078 */
    DWORD TlsBitmapBits[2]; /* 0x044 0x080 */
    void *ReadOnlySharedMemoryBase; /* 0x04c 0x088 */
    void *SharedData; /* 0x050 0x090 */
    void **ReadOnlyStaticServerData; /* 0x054 0x098 */
    void *AnsiCodePageData; /* 0x058 0x0a0 */
    void *OemCodePageData; /* 0x05c 0x0a8 */
    void *UnicodeCaseTableData; /* 0x060 0x0b0 */
    DWORD NumberOfProcessors; /* 0x064 0x0b8 */
    DWORD NtGlobalFlag; /* 0x068 0x0bc */
    LARGE_INTEGER CriticalSectionTimeout; /* 0x070 0xc0 */
    UINT_PTR HeapSegmentReserve; /* 0x078 0xc8 */
    UINT_PTR HeapSegmentCommit; /* 0x07c 0x0d0 */
    UINT_PTR HeapDeCommitTotalFreeThreshold; /* 0x080 0x0d8 */
    UINT_PTR HeapDeCommitFreeBlockThreshold; /* 0x084 0x0e0 */
    DWORD NumberOfHeaps; /* 0x088 0x0e8 */
    DWORD MaximumNumberOfHeaps; /* 0x08c 0x0ec */
    void **ProcessHeaps; /* 0x090 0x0f0 */
    void *GdiSharedHandleTable; /* 0x094 0x0f8 */
    void *ProcessStarterHelper; /* 0x098 0x100 */
    DWORD GdiDCAttributeList; /* 0x09c 0x108 */
    void *LoaderLock; /* 0x0a0 0x110 RTL_CRITICAL_SECTION* */
    DWORD OSMajorVersion; /* 0x0a4 0x118 */
    DWORD OSMinorVersion; /* 0x0a8 0x11c */
    WORD OSBuildNumber; /* 0x0ac 0x120 */
    WORD OSCSDVersion; /* 0x0ae 0x122 */
    DWORD OSPlatformId; /* 0x0b0 0x124 */
    DWORD ImageSubsystem; /* 0x0b4 0x128 */
    DWORD ImageSubsystemMajorVersion; /* 0x0b8 0x12c */
    DWORD ImageSubsystemMinorVersion; /* 0x0bc 0x130 */
    UINT_PTR ActiveProcessAffinityMask; /* 0x0c0 0x138 */
#if defined(__x86_64)
    DWORD GdiHandleBuffer[60]; /* 0x0c4 0x140 */
#elif defined(__i386__)
    DWORD GdiHandleBuffer[34]; /* 0x0c4 0x140 */
#else
#    warning Unsupported architecture
#endif
    void *PostProcessInitRoutine; /* 0x014c 0x230 */
    void *TlsExpansionBitmap; /* 0x150 0x238 */
    DWORD TlsExpansionBitmapBits[32]; /* 0x154 0x240 */
    ULONG SessionId; /* 0x1d4 0x2c0 */
} PEB, *PPEB;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* NT_TIB conflicts with a definition in winnt.h header from MinGW */
typedef struct _NT_TIB_redef {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList; /* 0x00 0x00 */
    PVOID StackBase; /* 0x04 0x08 */
    PVOID StackLimit; /* 0x08 0x10 */
    PVOID SubSystemTib; /* 0x0c 0x18 */
    union {
        PVOID FiberData; /* 0x10 0x20 */
        DWORD Version;
    };
    PVOID ArbitraryUserPointer; /* 0x14 0x28 */
    struct _NT_TIB *Self; /* 0x18 0x30 */
} NT_TIB_redef, *PNT_TIB_redef;
#define NT_TIB NT_TIB_redef

#pragma pack(push,1)
typedef struct _TEB_internal {
    NT_TIB NtTib; /* 0x000 0x000 */
    PVOID EnvironmentPointer; /* 0x01c 0x038 */
    CLIENT_ID ClientId; /* 0x020 0x040 */
    PVOID ActiveRpcHandle; /* 0x028 0x050 */
    PVOID ThreadLocalStoragePointer; /* 0x02c 0x058 */
    PPEB ProcessEnvironmentBlock; /* 0x030 0x060 */
    ULONG LastErrorValue; /* 0x034 0x068 */
    DWORD CountOfOwnedCriticalSections; /* 0x038 0x06c */
    void *CsrClientThread; /* 0x03c 0x070 */
    void *Win32ThreadInfo; /* 0x040 0x078 */
    DWORD User32Reserved[26]; /* 0x044 0x080 */
    DWORD UserReserved[5]; /* 0x0ac 0x0e8 */
    void *WOW32Reserved; /* 0x0c0 0x100 On WoW64, this is a function pointer to an x86-64 syscall wrapper */
    DWORD CurrentLocale; /* 0x0c4 0x108 */
    DWORD FpSoftwareStatusRegister; /* 0x0c8 0x10c */
} TEB_internal, *PTEB_internal;
#pragma pack(pop)

typedef struct _KSYSTEM_TIME {
    ULONG LowPart; /* 0 */
    LONG High1Time; /* 4 */
    LONG High2Time; /* 8 */
} KSYSTEM_TIME, *PKSYSTEM_TIME; /* size: 0x000c */

/* Shared user data at 0x7ffe0000, defined as MM_SHARED_USER_DATA_VA in Windows SDK.
 * http://terminus.rewolf.pl/terminus/structures/ntdll/_KUSER_SHARED_DATA_combined.html
 */
typedef struct _KUSER_SHARED_DATA {
    DWORD TickCountLowDeprecated; /* 0x000 */
    DWORD TickCountMultiplier; /* 0x004 */
    volatile KSYSTEM_TIME InterruptTime; /* 0x008 */
    volatile KSYSTEM_TIME SystemTime; /* 0x014 time in units of 100 ns since January 1, 1601 */
    volatile KSYSTEM_TIME TimeZoneBias; /* 0x020 */
    WORD ImageNumberLow; /* 0x02c */
    WORD ImageNumberHigh; /* 0x02e */
    WCHAR NtSystemRoot[260]; /* 0x030 */
    DWORD MaxStackTraceDepth; /* 0x238 */
    DWORD CryptoExponent; /* 0x23c */
    DWORD TimeZoneId; /* 0x240 */
    DWORD LargePageMinimum; /* 0x244 */
    DWORD AitSamplingValue; /* 0x248 */
    DWORD AppCompatFlag; /* 0x24c */
    unsigned __int64 RNGSeedVersion; /* 0x250 */
    DWORD GlobalValidationRunlevel; /* 0x258 */
    volatile DWORD TimeZoneBiasStamp; /* 0x25c */
    DWORD NtBuildNumber; /* 0x260 */
    DWORD NtProductType; /* 0x264 */
    BYTE ProductTypeIsValid; /* 0x268 */
    BYTE Reserved0[1]; /* 0x269 */
    WORD NativeProcessorArchitecture; /* 0x26a */
    DWORD NtMajorVersion; /* 0x26c */
    DWORD NtMinorVersion; /* 0x270 */
    BYTE ProcessorFeatures[64]; /* 0x274 */
    DWORD Reserved1; /* 0x2b4 */
    DWORD Reserved3; /* 0x2b8 */
    volatile DWORD TimeSlip; /* 0x2bc */
    DWORD AlternativeArchitecture; /* 0x2c0 */
    DWORD BootId; /* 0x2c4 */
    LARGE_INTEGER SystemExpirationDate; /* 0x2c8 */
    DWORD SuiteMask; /* 0x2d0 */
    BYTE KdDebuggerEnabled; /* 0x2d4 */
    BYTE MitigationPolicies; /* 0x2d5 */
    WORD CyclesPerYield; /* 0x2d6 */
    volatile DWORD ActiveConsoleId; /* 0x2d8 */
    volatile DWORD DismountCount; /* 0x2dc */
    DWORD ComPlusPackage; /* 0x2e0 */
    DWORD LastSystemRITEventTickCount; /* 0x2e4 */
    DWORD NumberOfPhysicalPages; /* 0x2e8 */
    BYTE SafeBootMode; /* 0x2ec */
    BYTE VirtualizationFlags; /* 0x2ed */
    BYTE Reserved12[2]; /* 0x2ee */
    DWORD SharedDataFlags; /* 0x2f0 */
    DWORD DataFlagsPad[1]; /* 0x2f4 */
    unsigned __int64 TestRetInstruction; /* 0x2f8 */
    unsigned __int64 QpcFrequency; /* 0x300 */
    DWORD SystemCall; /* 0x308 */
    DWORD UserCetAvailableEnvironments; /* 0x30c */
    unsigned __int64 SystemCallPad[2]; /* 0x310 */
    volatile KSYSTEM_TIME TickCount; /* 0x320 */
    DWORD TickCountPad[1]; /* 0x32c */
    DWORD Cookie; /* 0x330 for EncodeSystemPointer/DecodeSystemPointer */
    DWORD CookiePad[1]; /* 0x334 */
    unsigned __int64 ConsoleSessionForegroundProcessId; /* 0x338 */
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

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
static const TEB_internal *_NtCurrentTeb(VOID)
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
static const PEB *_NtCurrentPeb(VOID)
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
