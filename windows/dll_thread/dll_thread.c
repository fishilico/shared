/**
 * Simple DLL for Windows, with TLS support.
 * DLL: Dynamic Link Library
 * TLS: Thread-Local-Storage (TLS)
 *
 * Documentation: http://www.mingw.org/wiki/sampleDLL
*/
#include <inttypes.h>
#include <stdio.h>
#include "dll_thread.h"

#define printerr(format, ...) fprintf(stderr, "[%s] " format "\n", __FUNCTION__, ##__VA_ARGS__)

static DWORD g_dwTlsIndex = 0;

/**
 * Say hello
 */
DLLIMPORT void hello_world(void)
{
    printf("[DLL] Hello, world !\n");
}

/**
 * Allocate TLS data
 */
static BOOL dlltls_alloc_data(void)
{
    LPVOID lpvData;
    /* Return TRUE if data is already allocated */
    lpvData = TlsGetValue(g_dwTlsIndex);
    if (lpvData)
        return TRUE;

    lpvData = (LPVOID)LocalAlloc(LPTR, DLL_TLS_SIZE);
    if (!lpvData) {
        printerr("LocalAlloc failed");
        return FALSE;
    }
    if (!TlsSetValue(g_dwTlsIndex, lpvData)) {
        printerr("TlsSetValue failed");
        return FALSE;
    }
    return TRUE;
}

/**
 * Free TLS data
 */
static BOOL dlltls_free_data(void)
{
    LPVOID lpvData;
    lpvData = TlsGetValue(g_dwTlsIndex);
    if (!lpvData)
        return FALSE;

    LocalFree((HLOCAL)lpvData);
    if (!TlsSetValue(g_dwTlsIndex, NULL)) {
        printerr("TlsSetValue(NULL) failed");
        return FALSE;
    }
    return TRUE;
}

/**
 * Get a pointer to TLS data
 */
DLLIMPORT LPVOID dll_thread_tls_data(void)
{
    return TlsGetValue(g_dwTlsIndex);
}

/**
 * DLL Entry Point
 */
#define mainlog(format, ...) printf("[%s @%"PRIxPTR"] " format "\n", __FUNCTION__, (UINT_PTR)hinstDLL, ##__VA_ARGS__)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, __UNUSED_PARAM(LPVOID lpvReserved))
{
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            mainlog("Process Attach from module @%" PRIxPTR " (%s)",
                    (UINT_PTR)GetModuleHandle(NULL),
                    (lpvReserved != NULL) ? "static load" : "LoadLibrary call");
            g_dwTlsIndex = TlsAlloc();
            if (g_dwTlsIndex == TLS_OUT_OF_INDEXES) {
                printerr("TlsAlloc failed: no more TLS Indexes");
                return FALSE;
            }
            mainlog("-> New TLS Index: %lu", g_dwTlsIndex);
            if (!dlltls_alloc_data()) {
                printerr("Unable to initialize TLS");
                return FALSE;
            }
            break;
        case DLL_THREAD_ATTACH:
            mainlog("Thread Attach");
            if (!dlltls_alloc_data()) {
                printerr("Unable to initialize TLS");
                return FALSE;
            }
            break;
        case DLL_THREAD_DETACH:
            mainlog("Thread Detach");
            dlltls_free_data();
            break;
        case DLL_PROCESS_DETACH:
            mainlog("Process Detach (%s)",
                    (lpvReserved != NULL) ? "dying process" : "FreeLibrary call");
            dlltls_free_data();
            TlsFree(g_dwTlsIndex);
            break;
        default:
            mainlog("dwReason %lu unknown", dwReason);
    }
    return TRUE;
}
