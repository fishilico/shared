/**
 * Common header for some windows_examples programs
 */
#ifndef WINDOWS_EXAMPLES_COMMON_H
#define WINDOWS_EXAMPLES_COMMON_H

/* -municode defines UNICODE but not _UNICODE */
#ifndef UNICODE
#    undef _UNICODE
#elif !defined(_UNICODE)
#    define _UNICODE
#endif

/* Always-included headers */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>

/* Define ARRAYSIZE if not found */
#ifndef ARRAYSIZE
#    define ARRAYSIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif

/* Stringify a value like an integer */
#ifndef STR
#    define _STR(x) #x
#    define STR(x) _STR(x)
#endif

/* Print format for ANSI and wide-char string in _tprintf */
#if defined(UNICODE)
#    define PRIsA "S"
#    define PRIsW "s"
#else
#    define PRIsA "s"
#    define PRIsW "S"
#endif

/* Print format for OLE strings (LPOLESTR, LPCOLESTR, BSTR) */
#if defined(OLE2ANSI)
#    define PRIsOLE PRIsA
#else
#    define PRIsOLE PRIsW
#endif


/**
 * Print the last Windows error
 */
static void print_winerr(LPCTSTR szMessage)
{
    DWORD dwLastErr;
    LPTSTR lpLastErrMsgBuf = NULL;
    TCHAR c;

    dwLastErr = GetLastError();
    if (!FormatMessage(
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
            c = lpLastErrMsgBuf[--len];
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
static LPCTSTR StringListNext(LPCTSTR str, LPCTSTR base, DWORD cchMax)
{
    size_t cchLength;
    LPCTSTR end;
    end = _tcsninc(base, cchMax);
    assert(base && base <= str && str < end);
    if (!str[0]) {
        return NULL;
    }
#ifdef _tcscnlen
    cchLength = _tcscnlen(str, cchMax);
#else
    cchLength = min(_tcslen(str), cchMax);
#endif
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
/* ParamBufSizeToAlloc:
 * There is an IN parameter for the size of the provided buffer
 * and an OUT parameter for the size used
 */
#define _ParamBufSizeToAlloc_PROLOG(buftype, sizevar, pretsizevar) \
    BOOL bSuccess; \
    buftype pBuffer; \
    DWORD sizevar = 0; \
    if (pretsizevar) { \
        *pretsizevar = 0; \
    }
#define _ParamBufSizeToAlloc_ALLOC(fctname, allocsize) \
    if (bSuccess) { \
        _ftprintf(stderr, _T(fctname ": unexpected success\n")); \
        return NULL; \
    } \
    pBuffer = HeapAlloc(GetProcessHeap(), 0, allocsize); \
    if (!pBuffer) { \
        print_winerr(_T("HeapAlloc")); \
        return NULL; \
    }
#define _ParamBufSizeToAlloc_EPILOG(fctname, sizevar, pretsizevar) \
    if (!bSuccess) { \
        print_winerr(_T(fctname)); \
        HeapFree(GetProcessHeap(), 0, pBuffer); \
        return NULL; \
    } \
    assert(!pretsizevar || *pretsizevar <= sizevar); \
    return pBuffer;

#define _ParamBufSizeToAlloc2(f, type1, param1, type2, param2) \
    static LPVOID f##_a(type1 param1, type2 param2, PDWORD pcbReturnLength) \
    { \
        _ParamBufSizeToAlloc_PROLOG(LPVOID, cbLength, pcbReturnLength) \
        bSuccess = f(param1, param2, NULL, 0, &cbLength); \
        _ParamBufSizeToAlloc_ALLOC(#f, cbLength) \
        bSuccess = f(param1, param2, pBuffer, cbLength, pcbReturnLength); \
        _ParamBufSizeToAlloc_EPILOG(#f, cbLength, pcbReturnLength) \
    }

/* ParamStringBufSizeToAlloc:
 * There is an IN parameter for the length of the provided string buffer (PTSTR)
 * and an OUT parameter for the length used
 */
#define _ParamStringBufSizeToAlloc1(f, type1, param1) \
    static LPTSTR f##_a(type1 param1, PDWORD pcchReturnLength) \
    { \
        _ParamBufSizeToAlloc_PROLOG(LPTSTR, cchLength, pcchReturnLength) \
        bSuccess = f(param1, NULL, 0, &cchLength); \
        _ParamBufSizeToAlloc_ALLOC(#f, cchLength * sizeof(TCHAR)) \
        bSuccess = f(param1, pBuffer, cchLength, pcchReturnLength); \
        _ParamBufSizeToAlloc_EPILOG(#f, cchLength, pcchReturnLength) \
    }

/* ParamStringBufInOutSizeToAlloc:
 * The length of the output string is an INOUT parameter
 */
#define _ParamStringBufInOutSizeToAlloc_PROLOG() \
    DWORD cchLength2 = 0; \
    _ParamBufSizeToAlloc_PROLOG(LPTSTR, cchLength, pcchReturnLength) \
    if (!pcchReturnLength) { \
        pcchReturnLength = &cchLength2; \
    }
#define _ParamStringBufInOutSizeToAlloc_ALLOC(fctname) \
    _ParamBufSizeToAlloc_ALLOC(fctname, cchLength * sizeof(TCHAR)) \
    *pcchReturnLength = cchLength;
#define _ParamStringBufInOutSizeToAlloc_EPILOG(fctname) \
    _ParamBufSizeToAlloc_EPILOG(fctname, cchLength, pcchReturnLength)

#define _ParamStringBufInOutSizeToAlloc0(f) \
    static LPTSTR f##_stra(PDWORD pcchReturnLength) \
    { \
        _ParamStringBufInOutSizeToAlloc_PROLOG() \
        bSuccess = f(NULL, &cchLength); \
        _ParamStringBufInOutSizeToAlloc_ALLOC(#f) \
        bSuccess = f(pBuffer, pcchReturnLength); \
        _ParamStringBufInOutSizeToAlloc_EPILOG(#f) \
    }

#define _ParamStringBufInOutSizeToAlloc1(f, type1, param1) \
    static LPTSTR f##_stra(type1 param1, PDWORD pcchReturnLength) \
    { \
        _ParamStringBufInOutSizeToAlloc_PROLOG() \
        bSuccess = f(param1, NULL, &cchLength); \
        _ParamStringBufInOutSizeToAlloc_ALLOC(#f) \
        bSuccess = f(param1, pBuffer, pcchReturnLength); \
        _ParamStringBufInOutSizeToAlloc_EPILOG(#f) \
    }

#define _ParamStringBufInOutSizeToAlloc2(f, type1, param1, type2, param2) \
    static LPTSTR f##_stra(type1 param1, type2 param2, PDWORD pcchReturnLength) \
    { \
        _ParamStringBufInOutSizeToAlloc_PROLOG() \
        bSuccess = f(param1, param2, NULL, &cchLength); \
        _ParamStringBufInOutSizeToAlloc_ALLOC(#f) \
        bSuccess = f(param1, param2, pBuffer, pcchReturnLength); \
        _ParamStringBufInOutSizeToAlloc_EPILOG(#f) \
    }

#endif /* WINDOWS_EXAMPLES_COMMON_H */
