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
#include <assert.h>
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
    } else {
        /* Strip end of line */
        size_t len = _tcslen(lpLastErrMsgBuf);
        while (len > 0) {
            len--;
            TCHAR c = lpLastErrMsgBuf[len];
            if (c != _T('\n') && c != _T('\r')) {
                break;
            }
        }
        lpLastErrMsgBuf[len] = 0;
    }
    _ftprintf(stderr, _T("%s: error %lu, %s\n"), szMessage, dwLastErr,
        lpLastErrMsgBuf ? lpLastErrMsgBuf : _T("(unknown)"));
    if (lpLastErrMsgBuf) {
        LocalFree(lpLastErrMsgBuf);
    }
}

/**
 * Get the next item in a list of strings
 * "str" is an item of the list beginning at "base" and containing at most
 * cchMax characters.
 */
static LPCTSTR StringListNext(LPCTSTR str, LPCTSTR base, DWORD cchMax) {
    size_t cchLength;
    LPCTSTR end;
    end = _tcsninc(base, cchMax);
    assert(base && base <= str && str < end);
    if (!str[0]) {
        return NULL;
    }
    cchLength = _tcscnlen(str, cchMax);
    str = _tcsninc(str, cchLength + 1);
    assert(str < end);
    return str;
}

#define foreach_str(item, list, cchMax) \
    for (item = (list); *item; item = StringListNext(item, (list), cchMax))

/**
 * Transform a function which list of parameters ends with "output buffer, input size, output size"
 * to a function which allocate the buffer on the Heap.
 * According to the number of other parameters, the macro differs.
 */
#define _ParamStringBufSizeToAlloc1(f, type1, param1) \
    static LPTSTR f##_a(type1 param1, PDWORD pcchReturnLength) \
    { \
        BOOL bSuccess; \
        LPTSTR pszBuffer; \
        DWORD cchLength = 0; \
        if (pcchReturnLength) { \
            *pcchReturnLength = 0; \
        } \
        bSuccess = f(param1, NULL, 0, &cchLength); \
        if (bSuccess) { \
            _ftprintf(stderr, _T(#f": unexpected success\n")); \
            return NULL; \
        } \
        pszBuffer = HeapAlloc(GetProcessHeap(), 0, cchLength * sizeof(TCHAR)); \
        if (!pszBuffer) { \
            print_winerr(_T("HeapAlloc")); \
            return NULL; \
        } \
        bSuccess = f(param1, pszBuffer, cchLength, pcchReturnLength); \
        if (!bSuccess) { \
            print_winerr(_T(#f)); \
            HeapFree(GetProcessHeap(), 0, pszBuffer); \
            return NULL; \
        } \
        assert(!pcchReturnLength || *pcchReturnLength <= cchLength); \
        return pszBuffer; \
    }

#endif /* WINDOWS_EXAMPLES_COMMON_H */
