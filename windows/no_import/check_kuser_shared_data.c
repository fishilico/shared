/**
 * Check the content of the KUSER_SHARED_DATA structure.
 *
 * This structure is always located at address 0x7ffe0000 in usermode address
 * space and address KI_USER_SHARED_DATA in kernelmode address space:
 * * 0xffdf0000 on x86
 * * 0xffff9000 on ARM
 * * 0xfffff780_00000000 on x86_64
 *
 * This structure can be dumped using WinDbg's extension !kuser:
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-kuser
 */
#include <assert.h>
#include <stdio.h>
#include <tchar.h>
#include "internal_structures.h"

/* Print format for ANSI and wide-char string in _tprintf */
#if defined(UNICODE)
#    define PRIsA "S"
#    define PRIsW "s"
#else
#    define PRIsA "s"
#    define PRIsW "S"
#endif

/**
 * Read a KSYSTEM_TIME structure in an order describe in
 * https://www.dcl.hpi.uni-potsdam.de/research/WRK/2007/08/getting-os-information-the-kuser_shared_data-structure/
 */
static unsigned __int64 read_time(volatile KSYSTEM_TIME *pTime)
{
    ULONG myLowPart;
    LONG myHigh1Time, myHigh2Time;

    do {
        myHigh1Time = pTime->High1Time;
        myLowPart = pTime->LowPart;
        myHigh2Time = pTime->High2Time;
    } while (myHigh1Time != myHigh2Time);
    return (((unsigned __int64)myHigh1Time) << 32) | myLowPart;
}

int _tmain(void)
{
    /* Hard-code the address to the shared user data */
    KUSER_SHARED_DATA *const pSharedData = (KUSER_SHARED_DATA *)0x7ffe0000;
    unsigned __int64 tick_count;

    /* Check internal structure offsets */
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountMultiplier) == 0x004);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTime) == 0x008);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemTime) == 0x014);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBias) == 0x020);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtSystemRoot) == 0x030);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtBuildNumber) == 0x260);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtProductType) == 0x264);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMajorVersion) == 0x26c);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMinorVersion) == 0x270);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, BootId) == 0x2c4);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, KdDebuggerEnabled) == 0x2d4);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, MitigationPolicies) == 0x2d5);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveConsoleId) == 0x2d8);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, DismountCount) == 0x2dc);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TestRetInstruction) == 0x2f8);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCount) == 0x320);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Cookie) == 0x330);
    BUILTTIME_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ConsoleSessionForegroundProcessId) == 0x338);

    _tprintf(_T("TickCountMultiplier: %lu (%#lx)\n"),
             pSharedData->TickCountMultiplier, pSharedData->TickCountMultiplier);
    _tprintf(_T("InterruptTime: %I64u\n"), read_time(&pSharedData->InterruptTime));
    /* Convert the System Time using Python:
     * import datetime;print(datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=SystemTime//10))
     */
    _tprintf(_T("SystemTime: %I64u\n"), read_time(&pSharedData->SystemTime));
    _tprintf(_T("TimeZoneBias: %I64u\n"), read_time(&pSharedData->TimeZoneBias));
    tick_count = read_time(&pSharedData->TickCount);
    _tprintf(_T("TickCount: %I64u\n"), tick_count);
    _tprintf(_T("... Low part(TickCount): %lu\n"), (DWORD)(tick_count & 0xffffffff));
    _tprintf(_T("... GetTickCount(): %lu\n"), GetTickCount());
    _tprintf(_T("\n"));

    _tprintf(_T("NtSystemRoot: %.260" PRIsW "\n"), pSharedData->NtSystemRoot);
    if (!StringsCaseLenEqualsW(L"C:\\windows", pSharedData->NtSystemRoot, 260)) {
        _tprintf(_T("Unexpected NtSystemRoot: not C:\\windows\n"));
        return 1;
    }

    _tprintf(_T("ImageNumber: %#x ... %#x\n"), pSharedData->ImageNumberLow, pSharedData->ImageNumberHigh);
    _tprintf(_T("CryptoExponent: %#lx\n"), pSharedData->CryptoExponent);
    _tprintf(_T("TimeZoneId: %#lx\n"), pSharedData->TimeZoneId);
    _tprintf(_T("\n"));

    _tprintf(_T("OS version: %lu.%lu build %lu\n"),
             pSharedData->NtMajorVersion, pSharedData->NtMinorVersion, pSharedData->NtBuildNumber);
    _tprintf(_T("NtProductType: %lu (1 for WinNT, 2 for LanManNT, 3 for Server)\n"),
             pSharedData->NtProductType);
    assert(pSharedData->NtProductType >= 1 && pSharedData->NtProductType <= 3);
    _tprintf(_T("ProductTypeIsValid: %u\n"), pSharedData->ProductTypeIsValid);
    assert(pSharedData->ProductTypeIsValid == 1);
    _tprintf(_T("NativeProcessorArchitecture: %u\n"), pSharedData->NativeProcessorArchitecture);
    _tprintf(_T("\n"));

    _tprintf(_T("MitigationPolicies: %#x\n"), pSharedData->MitigationPolicies);
    _tprintf(_T("  * NXSupportPolicy: %#x\n"), pSharedData->MitigationPolicies & 3);
    _tprintf(_T("  * SEHValidationPolicy: %#x\n"), (pSharedData->MitigationPolicies & 0xc) >> 2);
    _tprintf(_T("  * CurDirDevicesSkippedForDlls: %#x\n"), (pSharedData->MitigationPolicies & 0x30) >> 4);
    if (pSharedData->MitigationPolicies & ~0x3f) {
        _tprintf(_T("  * UNKNOWN: %#x\n"), pSharedData->MitigationPolicies & ~0x3f);
    }
    _tprintf(_T("\n"));

    _tprintf(_T("KdDebuggerEnabled: %u\n"), pSharedData->KdDebuggerEnabled);
    _tprintf(_T("ActiveConsoleId: %lu\n"), pSharedData->ActiveConsoleId);
    _tprintf(_T("DismountCount: %lu\n"), pSharedData->DismountCount);
    _tprintf(_T("ComPlusPackage: %lu\n"), pSharedData->ComPlusPackage);
    _tprintf(_T("NumberOfPhysicalPages: %lu\n"), pSharedData->NumberOfPhysicalPages);
    _tprintf(_T("SafeBootMode: %#x\n"), pSharedData->SafeBootMode);
    _tprintf(_T("VirtualizationFlags: %#x\n"), pSharedData->VirtualizationFlags);
    _tprintf(_T("\n"));

    _tprintf(_T("SharedDataFlags: %#lx\n"), pSharedData->SharedDataFlags);
    _tprintf(_T("  * DbgErrorPortPresent: %#lx\n"), pSharedData->SharedDataFlags & 1);
    _tprintf(_T("  * DbgElevationEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 2) >> 1);
    _tprintf(_T("  * DbgVirtEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 4) >> 2);
    _tprintf(_T("  * DbgInstallerDetectEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 8) >> 3);
    _tprintf(_T("  * DbgLkgEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 8) >> 3);
    _tprintf(_T("  * DbgDynProcessorEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 0x10) >> 4);
    _tprintf(_T("  * DbgConsoleBrokerEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 0x20) >> 5);
    _tprintf(_T("  * DbgSecureBootEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 0x40) >> 6);
    _tprintf(_T("  * DbgMultiSessionSku: %#lx\n"), (pSharedData->SharedDataFlags & 0x80) >> 7);
    _tprintf(_T("  * DbgMultiUsersInSessionSku: %#lx\n"), (pSharedData->SharedDataFlags & 0x100) >> 8);
    _tprintf(_T("  * DbgStateSeparationEnabled: %#lx\n"), (pSharedData->SharedDataFlags & 0x200) >> 9);
    if (pSharedData->SharedDataFlags & ~0x3ff) {
        _tprintf(_T("  * UNKNOWN SpareBits: %#lx\n"), pSharedData->SharedDataFlags & ~0x3ff);
    }
    _tprintf(_T("\n"));

    _tprintf(_T("TestRetInstruction: %#I64x\n"), pSharedData->TestRetInstruction);
    if (pSharedData->TestRetInstruction == 0) {
        /* 0 is used on Wine */
    } else if (pSharedData->TestRetInstruction == 0xc3) {
        /* "C3" is RET on x86 */
    } else {
        _tprintf(_T("Unexpected TestRetInstruction: not 0xc3\n"));
        return 1;
    }
    _tprintf(_T("Cookie: %#lx\n"), pSharedData->Cookie);
    _tprintf(_T("ConsoleSessionForegroundProcessId: %I64u\n"),
             pSharedData->ConsoleSessionForegroundProcessId);

    return 0;
}
