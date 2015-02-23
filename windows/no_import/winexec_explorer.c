/**
 * Start explorer.exe using WinExec
 *
 * This is an old API which can be used to launch graphical applications.
 * It uses CreateProcess.
 * Wine source:
 * https://source.winehq.org/source/dlls/kernel32/process.c?%21v=wine-1.7.36#2551
 */
#include "internal_structures.h"
#include "noimport_start.h"

static int _main(void)
{
    UINT (WINAPI *pfnWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
    UINT ret;

    pfnWinExec = _GetKernel32ProcAddress("WinExec");
    if (!pfnWinExec) {
        return 1;
    }
    ret = pfnWinExec("explorer", SW_SHOWNORMAL);
    if (ret < 32) {
        return 1;
    }
    return 0;
}
