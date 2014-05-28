/**
 * Check that WinMain arguments can be found through Windows API
 */
#include <windows.h>
#include <stdio.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HINSTANCE hInstance2;
    LPSTR lpCmdLine2;
    int nCmdShow2, n;
    STARTUPINFO startupInfo;
    BOOL isOk;
    char message[4096];
    char *szBuf = message;
    size_t nRemaining = sizeof(message);

    hInstance2 = GetModuleHandle(NULL);
    lpCmdLine2 = GetCommandLine() - 1;
    while (*lpCmdLine2 && *lpCmdLine2 != ' ') {
        lpCmdLine2++;
    }
    while (*lpCmdLine2 == ' ') {
        lpCmdLine2++;
    }
    GetStartupInfo(&startupInfo);
    nCmdShow2 = (startupInfo.dwFlags & STARTF_USESHOWWINDOW) ? startupInfo.wShowWindow : SW_SHOWDEFAULT;

    isOk = TRUE;
    if (hInstance != hInstance2) {
        n = snprintf(szBuf, nRemaining, "Unexpected hInstance (%p != %p)\n", hInstance, hInstance2);
        isOk = FALSE;
    } else {
        n = snprintf(szBuf, nRemaining, "hInstance = %p\n", hInstance);
    }
    szBuf += n;
    nRemaining -= n;
    if (hPrevInstance != NULL) {
        n = snprintf(szBuf, nRemaining, "Unexpected hPrevInstance (%p != %p)\n", hPrevInstance, NULL);
        isOk = FALSE;
    } else {
        n = snprintf(szBuf, nRemaining, "hPrevInstance = NULL\n");
    }
    szBuf += n;
    nRemaining -= n;
    if (lpCmdLine != lpCmdLine2 && lstrcmp(lpCmdLine, lpCmdLine2)) {
        n = snprintf(szBuf, nRemaining, "Unexpected lpCmdLine (%p != %p)\n", lpCmdLine, lpCmdLine2);
        isOk = FALSE;
    } else {
        n = snprintf(szBuf, nRemaining, "lpCmdLine = %p\n", lpCmdLine);
    }
    szBuf += n;
    nRemaining -= n;
    if (nCmdShow != nCmdShow2) {
        n = snprintf(szBuf, nRemaining, "Unexpected nCmdShow (%d != %d)\n", nCmdShow, nCmdShow2);
        isOk = FALSE;
    } else {
        n = snprintf(szBuf, nRemaining, "nCmdShow = %d%s\n", nCmdShow, (nCmdShow == SW_SHOWDEFAULT) ? " (SW_SHOWDEFAULT)" : "");
    }
    szBuf += n;
    nRemaining -= n;
    if (isOk) {
        snprintf(szBuf, nRemaining, "Every WinMain parameter is fine :)");
    } else {
        snprintf(szBuf, nRemaining, "There have been problems with WinMain parameters");
    }
    message[sizeof(message) - 1] = '\0';
    MessageBoxA(NULL, message, "WinMain params", MB_ICONINFORMATION | MB_OK);
    return isOk ? 0 : 1;
}
