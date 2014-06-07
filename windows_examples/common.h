/**
 * Common header for some windows_examples programs
 */
#ifndef WINDOWS_EXAMPLES_COMMON_H
#define WINDOWS_EXAMPLES_COMMON_H

/* Always-included headers */
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * Print the last Windows error
 */
static void print_winerr(const char *message)
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
    fprintf(stderr, "%s: error %lu, %s\n", message, dwLastErr,
        lpLastErrMsgBuf ? lpLastErrMsgBuf : "(unknown)");
    if (lpLastErrMsgBuf) {
        LocalFree(lpLastErrMsgBuf);
    }
}

#endif /* WINDOWS_EXAMPLES_COMMON_H */
