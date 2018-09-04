/**
 * Display information about the current host
 */
#include "common.h"

_ParamStringBufInOutSizeToAlloc0(GetComputerName);
_ParamStringBufInOutSizeToAlloc0(GetUserName);

int _tmain(void)
{
    LPTSTR szComputerName, szUserName;
    OSVERSIONINFOEX ovi;
    SYSTEM_INFO sysi;
    LPCTSTR szPlatform = _T("");
    HMODULE hKernel;
    VOID (WINAPI *pfnGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);

    /* Computer name */
    szComputerName = GetComputerName_a(NULL);
    _tprintf(_T("Computer name: %s\n"), szComputerName ? : _T("?"));
    HeapFree(GetProcessHeap(), 0, szComputerName);

    /* User name */
    szUserName = GetUserName_a(NULL);
    _tprintf(_T("User name: %s\n"), szUserName ? : _T("?"));
    HeapFree(GetProcessHeap(), 0, szUserName);

    /* OS Version:
     * Win32s        = Windows 3.1?
     * Win32 OT 4.0  = Windows 95
     * Win32 OT 4.10 = Windows 98
     * Win32 OT 4.90 = Windows Me
     * Win32 NT 3.*  = Windows NT 3
     * Win32 NT 4.*  = Windows NT 4
     * Win32 NT 5.0  = Windows 2000
     * Win32 NT 5.1  = Windows XP
     * Win32 NT 5.2  = Windows XP Pro or Server 2003
     * Win32 NT 6.0  = Windows Vista or Server 2008
     * Win32 NT 6.1  = Windows 7 or Server 2008 R2
     * Win32 NT 6.2  = Windows 8 or Server 2012
     * Win32 NT 6.3  = Windows 8.1 or Server 2012 R2
     * Win32 NT 10   = Windows 10
     */
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    if (!GetVersionEx((LPOSVERSIONINFO)&ovi)) {
        print_winerr(_T("GetVersionEx"));
        return 1;
    }
    switch (ovi.dwPlatformId) {
        case VER_PLATFORM_WIN32s:
            szPlatform = _T("Win32s");
            break;
        case VER_PLATFORM_WIN32_WINDOWS:
            szPlatform = _T("WinOT");
            break;
        case VER_PLATFORM_WIN32_NT:
            szPlatform = _T("WinNT");
            break;
        default:
            _tprintf(_T("Unknown OS platform %lu\n"), ovi.dwPlatformId);
            szPlatform = _T("?");
    }
    _tprintf(
        _T("OS version: %s %lu.%lu build %lu CSD \"%s\"\n"),
        szPlatform,
        ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber,
        ovi.szCSDVersion);
    _tprintf(_T("Product type: "));
    switch (ovi.wProductType) {
        case VER_NT_WORKSTATION:
            _tprintf(_T("Workstation"));
            break;
        case VER_NT_DOMAIN_CONTROLLER:
            _tprintf(_T("Domain Controller"));
            break;
        case VER_NT_SERVER:
            _tprintf(_T("Server"));
            break;
        default:
            _tprintf(_T("unknown (%u)"), ovi.wProductType);
    }
    _tprintf(_T("\n"));

    /* OS system information */
    ZeroMemory(&sysi, sizeof(sysi));
    hKernel = GetModuleHandle(_T("kernel32.dll"));
    if (!hKernel) {
        print_winerr(_T("GetModuleHandle(kernel32.dll)"));
        return 1;
    }
    pfnGetNativeSystemInfo = (VOID(WINAPI *) (LPSYSTEM_INFO)) (void *)GetProcAddress(hKernel, "GetNativeSystemInfo");
    if (pfnGetNativeSystemInfo) {
        pfnGetNativeSystemInfo(&sysi);
    } else {
        GetSystemInfo(&sysi);
    }
    _tprintf(_T("Processor architecture in %s: "),
             pfnGetNativeSystemInfo ? _T("GetNativeSystemInfo") : _T("GetSystemInfo"));
    switch (sysi.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            _tprintf(_T("x86_64"));
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            _tprintf(_T("arm"));
            break;
        case PROCESSOR_ARCHITECTURE_IA64:
            _tprintf(_T("ia64"));
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            _tprintf(_T("x86"));
            break;
        case PROCESSOR_ARCHITECTURE_UNKNOWN:
            _tprintf(_T("unknown"));
            break;
        default:
            _tprintf(_T("unknown (%u)"), sysi.wProcessorArchitecture);
    }
    _tprintf(_T("\n"));

    return 0;
}
