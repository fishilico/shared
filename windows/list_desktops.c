/**
 * List the current window stations and desktops
 */
#include "common.h"
#include <inttypes.h>

struct CURRENT_WINSTA_DESKTOP_CONTEXT {
    LPTSTR lpszWinstaName; /* name of the current window station */
    LPTSTR lpszDesktopName; /* name of the current desktop */
};

/* Wrap GetUserObjectInformation to allocate memory */
_ParamBufSizeToAlloc2(GetUserObjectInformation, HANDLE, hObj, int, nIndex)

/**
 * Return the name of the type associated with the given handle
 */
static LPTSTR GetUserObjectInformation_type(HANDLE hObj)
{
    return (LPTSTR)GetUserObjectInformation_a(hObj, UOI_TYPE, NULL);
}

/**
 * Return the name of the object associated with the given handle
 */
static LPTSTR GetUserObjectInformation_name(HANDLE hObj)
{
    return (LPTSTR)GetUserObjectInformation_a(hObj, UOI_NAME, NULL);
}

/**
 * Callback for EnumDesktopWindows
 */
static BOOL CALLBACK EnumDestktopWindowsProc(HWND hwnd, LPARAM lParam __attribute__((unused)))
{
    BOOL bVisible;
    UINT cchSize, cchLen;
    LPTSTR szClass, szTitle;
    DWORD dwProcessId = 0, dwThreadId;
    HMODULE hModule;
    HINSTANCE hInstance;

    bVisible = IsWindowVisible(hwnd);
    cchSize = MAX_PATH;
    szClass = HeapAlloc(GetProcessHeap(), 0, cchSize * sizeof(TCHAR));
    if (!szClass) {
        print_winerr(_T("HeapAlloc(szClass)"));
        return FALSE;
    }
    cchLen = GetClassName(hwnd, szClass, cchSize);
    assert(cchLen + 1 < cchSize && szClass[cchLen] == 0);

    cchSize = GetWindowTextLength(hwnd) + 2;
    szTitle = HeapAlloc(GetProcessHeap(), 0, cchSize * sizeof(TCHAR));
    if (!szTitle) {
        print_winerr(_T("HeapAlloc(szTitle)"));
        return FALSE;
    }
    cchLen = GetWindowText(hwnd, szTitle, cchSize);
    assert(cchLen + 1 < cchSize && szTitle[cchLen] == 0);

    dwThreadId = GetWindowThreadProcessId(hwnd, &dwProcessId);
    hModule = (HMODULE)GetClassLongPtr(hwnd, GCLP_HMODULE);
    hInstance = (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE);

    _tprintf(_T("    * [%#" PRIxPTR "] %c"), (UINT_PTR)hwnd, bVisible ? _T('V') : _T('-'));
    if (szClass) {
        _tprintf(_T(" (%s)"), szClass);
    }
    if (szTitle) {
        _tprintf(_T(" \"%s\""), szTitle);
    }
    _tprintf(_T(" PID %lu TID %lu"), dwProcessId, dwThreadId);
    if (hModule) {
        _tprintf(_T(" module @%p"), hModule);
    }
    if (hInstance && hInstance != hModule) {
        _tprintf(_T(" instance @%p"), hInstance);
    }
    _tprintf(_T("\n"));

    HeapFree(GetProcessHeap(), 0, szTitle);
    HeapFree(GetProcessHeap(), 0, szClass);
    CloseHandle(hModule);
    CloseHandle(hInstance);
    return TRUE;
}

/**
 * Callback for EnumDesktops
 */
static BOOL CALLBACK EnumDesktopProc(LPTSTR lpszDesktop, LPARAM lParam)
{
    struct CURRENT_WINSTA_DESKTOP_CONTEXT *pCtx = (struct CURRENT_WINSTA_DESKTOP_CONTEXT *)lParam;
    HDESK hDesktop;
    LPTSTR lpszType, lpszName;
    BOOL bResult;

    if (!pCtx) {
        /* OpenDesktop only works on desktops that belong to the current window
         * station. Only display the name of desktops for other Window stations.
         */
        _tprintf(_T("  * [Desktop] %s\n"), lpszDesktop);
        return TRUE;
    }

    /* An interesting flag may be DF_ALLOWOTHERACCOUNTHOOK: Allows processes
     * running in other accounts on the desktop to set hooks in this process.
     */
    hDesktop = OpenDesktop(lpszDesktop, 0, FALSE, DESKTOP_READOBJECTS);
    if (!hDesktop) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            /* The current user has not got access to everything */
            _tprintf(_T("  * [Desktop] (access denied) %s"), lpszDesktop);
            if (pCtx->lpszDesktopName && !_tcscmp(pCtx->lpszDesktopName, lpszDesktop)) {
                _tprintf(_T(" (current)"));
            }
            _tprintf(_T("\n"));
            return TRUE;
        }
        print_winerr(_T("OpenDesktop"));
        return FALSE;
    }
    lpszType = GetUserObjectInformation_type(hDesktop); /* type Desktop */
    lpszName = GetUserObjectInformation_name(hDesktop);
    _tprintf(_T("  * [%s] %s"), lpszType, lpszDesktop);
    if (lpszName) {
        if (_tcscmp(lpszDesktop, lpszName)) {
            _tprintf(_T(" (real name %s)\n"), lpszName);
        }
        if (pCtx->lpszDesktopName && !_tcscmp(pCtx->lpszDesktopName, lpszName)) {
            _tprintf(_T(" (current)"));
        }
    }
    _tprintf(_T("\n"));
    HeapFree(GetProcessHeap(), 0, lpszType);
    HeapFree(GetProcessHeap(), 0, lpszName);

    bResult = EnumDesktopWindows(hDesktop, EnumDestktopWindowsProc, (LPARAM)pCtx);
    if (!bResult) {
        print_winerr(_T("EnumDesktopWindows"));
    }
    CloseDesktop(hDesktop);
    return bResult;
}

/**
 * Callback for EnumWindowStations
 */
static BOOL CALLBACK EnumWindowStationProc(LPTSTR lpszWindowStation, LPARAM lParam)
{
    struct CURRENT_WINSTA_DESKTOP_CONTEXT *pCtx = (struct CURRENT_WINSTA_DESKTOP_CONTEXT *)lParam;
    HWINSTA hWinsta;
    LPTSTR lpszType, lpszName;
    BOOL bResult;

    hWinsta = OpenWindowStation(lpszWindowStation, FALSE, WINSTA_ENUMDESKTOPS);
    if (!hWinsta) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            /* The current user has not got access to everything */
            _tprintf(_T("* [WindowStation] (access denied) %s"), lpszWindowStation);
            if (pCtx && pCtx->lpszWinstaName && !_tcscmp(pCtx->lpszWinstaName, lpszWindowStation)) {
                _tprintf(_T(" (current)"));
            }
            _tprintf(_T("\n"));
            return TRUE;
        }
        print_winerr(_T("OpenWindowStation"));
        return FALSE;
    }
    lpszType = GetUserObjectInformation_type(hWinsta); /* type WindowStation */
    lpszName = GetUserObjectInformation_name(hWinsta);
    if (!lpszName) {
        _tprintf(_T("* [%s] %s (error %lu)"),
                 lpszType ? lpszType : _T("WindowStation"),
                 lpszWindowStation,
                 GetLastError());
        if (pCtx && pCtx->lpszWinstaName && !_tcscmp(pCtx->lpszWinstaName, lpszWindowStation)) {
            _tprintf(_T(" (current)"));
        } else {
            pCtx = NULL;
        }
    } else {
        _tprintf(_T("* [%s] %s"), lpszType, lpszWindowStation);
        if (_tcscmp(lpszWindowStation, lpszName)) {
            _tprintf(_T(" (real name %s)\n"), lpszName);
        }
        if (pCtx && pCtx->lpszWinstaName && !_tcscmp(pCtx->lpszWinstaName, lpszName)) {
            _tprintf(_T(" (current)"));
        } else {
            /* Do not forward the context to the desktop enumeration callback if it
             * is not the current window station.
             */
            pCtx = NULL;
        }
    }
    _tprintf(_T("\n"));
    HeapFree(GetProcessHeap(), 0, lpszType);
    HeapFree(GetProcessHeap(), 0, lpszName);

    bResult = EnumDesktops(hWinsta, EnumDesktopProc, (LPARAM)pCtx);
    if (!bResult) {
        print_winerr(_T("EnumDesktops"));
    }
    CloseWindowStation(hWinsta);
    return bResult;
}

int _tmain(int argc, TCHAR **argv)
{
    struct CURRENT_WINSTA_DESKTOP_CONTEXT ctx;
    HWINSTA hWinSta;
    HDESK hDesktop, hNewDesktop;
    BOOL bSwitchDesktop = FALSE;
    int i;

    for (i = 1; i < argc; i++) {
        if (!_tcscmp(argv[1], _T("-s"))) {
            bSwitchDesktop = TRUE;
        }
    }

    hWinSta = GetProcessWindowStation();
    if (!hWinSta) {
        print_winerr(_T("GetProcessWindowStation"));
        return 1;
    }
    hDesktop = GetThreadDesktop(GetCurrentThreadId());
    if (!hDesktop) {
        print_winerr(_T("GetThreadDesktop"));
        return 1;
    }
    ctx.lpszWinstaName = GetUserObjectInformation_name(hWinSta);
    ctx.lpszDesktopName = GetUserObjectInformation_name(hDesktop);
    _tprintf(_T("Current Window Station: handle %#" PRIxPTR ", name %s\n"), (UINT_PTR)hWinSta, ctx.lpszWinstaName);
    _tprintf(_T("Current Desktop: handle %#" PRIxPTR ", name %s\n"), (UINT_PTR)hDesktop, ctx.lpszDesktopName);

    if (!EnumWindowStations(EnumWindowStationProc, (LPARAM)&ctx)) {
        print_winerr(_T("EnumWindowStations"));
        HeapFree(GetProcessHeap(), 0, ctx.lpszWinstaName);
        HeapFree(GetProcessHeap(), 0, ctx.lpszDesktopName);
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, ctx.lpszWinstaName);
    HeapFree(GetProcessHeap(), 0, ctx.lpszDesktopName);

    if (bSwitchDesktop) {
        _tprintf(_T("Creating a new desktop\n"));
        hNewDesktop = CreateDesktop(_T("MyNewDesktopName"), NULL, NULL, 0, GENERIC_ALL, NULL);
        if (!hNewDesktop) {
            print_winerr(_T("CreateDesktop"));
            return 1;
        }
        _tprintf(_T("Switching to it for 5 seconds...\n"));
        SwitchDesktop(hNewDesktop);
        Sleep(5000);
        _tprintf(_T("... and switching back.\n"));
        CloseDesktop(hNewDesktop);
    }
    return 0;
}
