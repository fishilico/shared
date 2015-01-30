/**
 * List the current windows
 */
#include "common.h"

typedef struct _WINDOW_INFORMATIONS {
    HWND hwnd;
    LPTSTR szClass;
    LPTSTR szTitle;
    BOOL bVisible;
    DWORD dwProcessId;
    DWORD dwThreadId;
    HMODULE hModule;
    HINSTANCE hInstance;
} WINDOW_INFORMATIONS;

typedef struct _ENUM_WIN_INFOS_LPARAM {
    DWORD nCount;
    WINDOW_INFORMATIONS *infos;
} ENUM_WIN_INFOS_LPARAM;

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    ENUM_WIN_INFOS_LPARAM *pWininfos = (ENUM_WIN_INFOS_LPARAM *)lParam;
    WINDOW_INFORMATIONS *pInfo;
    DWORD i;
    int cchSize, cchLen;

    assert(pWininfos);

    /* Add one item to pWininfos->infos */
    i = pWininfos->nCount;
    pWininfos->nCount = i + 1;
    pInfo = pWininfos->infos;
    if (pInfo) {
        pInfo = HeapReAlloc(GetProcessHeap(), 0, pInfo, (i + 1) * sizeof(WINDOW_INFORMATIONS));
    } else {
        pInfo = HeapAlloc(GetProcessHeap(), 0, (i + 1) * sizeof(WINDOW_INFORMATIONS));
    }
    pWininfos->infos = pInfo;
    if (!pInfo) {
        print_winerr(_T("HeapRealloc"));
        return FALSE;
    }
    pInfo = &pInfo[i];
    ZeroMemory(pInfo, sizeof(*pInfo));

    /* Fill WINDOW_INFORMATIONS structure */
    pInfo->hwnd = hwnd;
    pInfo->bVisible = IsWindowVisible(hwnd);

    cchSize = MAX_PATH;
    pInfo->szClass = HeapAlloc(GetProcessHeap(), 0, cchSize * sizeof(TCHAR));
    if (!pInfo->szClass) {
        print_winerr(_T("HeapAlloc(szClass)"));
        return FALSE;
    }
    cchLen = GetClassName(hwnd, pInfo->szClass, cchSize);
    assert(cchLen + 1 < cchSize && pInfo->szClass[cchLen] == 0);

    cchSize = GetWindowTextLength(hwnd) + 2;
    pInfo->szTitle = HeapAlloc(GetProcessHeap(), 0, cchSize * sizeof(TCHAR));
    if (!pInfo->szTitle) {
        print_winerr(_T("HeapAlloc(szTitle)"));
        return FALSE;
    }
    cchLen = GetWindowText(hwnd, pInfo->szTitle, cchSize);
    assert(cchLen + 1 < cchSize && pInfo->szTitle[cchLen] == 0);

    pInfo->dwThreadId = GetWindowThreadProcessId(hwnd, &pInfo->dwProcessId);
    pInfo->hModule = (HMODULE)GetClassLongPtr(hwnd, GCLP_HMODULE);
    pInfo->hInstance = (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE);
    return TRUE;
}

static int CompareWinInfosList(const void *arg1, const void *arg2)
{
    const WINDOW_INFORMATIONS *pInfo1 = (const WINDOW_INFORMATIONS *)arg1;
    const WINDOW_INFORMATIONS *pInfo2 = (const WINDOW_INFORMATIONS *)arg2;
    int cmp;
    if (pInfo1->szTitle && !pInfo2->szTitle)
        return 1;
    if (!pInfo1->szTitle && pInfo2->szTitle)
        return -1;
    cmp = _tcsicmp(pInfo1->szTitle, pInfo2->szTitle);
    if (cmp)
        return cmp;

    if (pInfo1->szClass && !pInfo2->szClass)
        return 1;
    if (!pInfo1->szClass && pInfo2->szClass)
        return -1;
    cmp = _tcsicmp(pInfo1->szClass, pInfo2->szClass);
    if (cmp)
        return cmp;
    if (pInfo1->hwnd != pInfo2->hwnd)
        return (pInfo1->hwnd > pInfo2->hwnd) ? 1 : -1;
    return 0;
}

/**
 * Recursively list children of a given window
 */
static BOOL ListWindowsRec(HWND hwndParent, DWORD nIndent)
{
    BOOL bRet = TRUE;
    DWORD i, j;
    ENUM_WIN_INFOS_LPARAM wininfos;

    ZeroMemory(&wininfos, sizeof(wininfos));
    if (!hwndParent) {
        if (!EnumWindows(EnumWindowsProc, (LPARAM)&wininfos)) {
            print_winerr(_T("EnumWindows"));
            bRet = FALSE;
            goto cleanup;
        }
    } else {
        SetLastError(0);
        EnumChildWindows(hwndParent, EnumWindowsProc, (LPARAM)&wininfos);
        if (GetLastError()) {
            print_winerr(_T("EnumChildWindows"));
            bRet = FALSE;
            goto cleanup;
        }
    }

    if (wininfos.nCount) {
        assert(wininfos.infos);
        qsort(wininfos.infos, wininfos.nCount, sizeof(WINDOW_INFORMATIONS), CompareWinInfosList);
    }

    for (i = 0; i < wininfos.nCount; i++) {
        const WINDOW_INFORMATIONS *pInfo = &wininfos.infos[i];
        for (j = 0; j < nIndent; j++) {
            _tprintf(_T("  "));
        }
        _tprintf(_T("[%p] %c"), pInfo->hwnd, pInfo->bVisible ? _T('V') : _T('-'));
        if (pInfo->szClass) {
            _tprintf(_T(" (%s)"), pInfo->szClass);
        }
        if (pInfo->szTitle) {
            _tprintf(_T(" \"%s\""), pInfo->szTitle);
        }
        _tprintf(_T(" PID %lu TID %lu"), pInfo->dwProcessId, pInfo->dwThreadId);
        if (pInfo->hModule) {
            _tprintf(_T(" module @%p"), pInfo->hModule);
        }
        if (pInfo->hInstance && pInfo->hInstance != pInfo->hModule) {
            _tprintf(_T(" instance @%p"), pInfo->hInstance);
        }
        _tprintf(_T("\n"));
        if (!ListWindowsRec(pInfo->hwnd, nIndent + 1)) {
            bRet = FALSE;
            goto cleanup;
        }
    }

cleanup:
    if (wininfos.infos) {
        assert(wininfos.nCount > 0);
        for (i = 0; i < wininfos.nCount; i++) {
            HeapFree(GetProcessHeap(), 0, wininfos.infos[i].szClass);
            HeapFree(GetProcessHeap(), 0, wininfos.infos[i].szTitle);
            CloseHandle(wininfos.infos[i].hModule);
            CloseHandle(wininfos.infos[i].hInstance);
        }
        HeapFree(GetProcessHeap(), 0, wininfos.infos);
    }
    return bRet;
}

int _tmain(void)
{
    return ListWindowsRec(NULL, 0) ? 0 : 1;
}
