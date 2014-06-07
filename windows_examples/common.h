/**
 * Common header for some windows_examples programs
 */
#ifndef WINDOWS_EXAMPLES_COMMON_H
#define WINDOWS_EXAMPLES_COMMON_H

/* -municode defines UNICODE but not _UNICODE */
#ifndef UNICODE
#undef _UNICODE
#else
#ifndef _UNICODE
#define _UNICODE
#endif
#endif

/* Always-included headers */
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>

/**
 * Print the last Windows error
 */
static void print_winerr(LPCTSTR szMessage)
{
    DWORD dwLastErr;
    LPTSTR lpLastErrMsgBuf = NULL;

    dwLastErr = GetLastError();
    if(!FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dwLastErr,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpLastErrMsgBuf, 0, NULL)
    ) {
        lpLastErrMsgBuf = NULL;
    }
    _ftprintf(stderr, _T("%s: error %lu, %s\n"), szMessage, dwLastErr,
        lpLastErrMsgBuf ? lpLastErrMsgBuf : _T("(unknown)"));
    if (lpLastErrMsgBuf) {
        LocalFree(lpLastErrMsgBuf);
    }
}

#endif /* WINDOWS_EXAMPLES_COMMON_H */
