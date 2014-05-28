/**
 * C header for dll_thread.c
 */
#ifndef DLL_THREAD_H
#define DLL_THREAD_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#if BUILDING_DLL
#define DLLIMPORT __declspec(dllexport) __cdecl
#else
#define DLLIMPORT __declspec(dllimport) __cdecl
#endif

/**
 * Size of the TLS data
 */
#define DLL_TLS_SIZE 256

DLLIMPORT void hello_world(void);
DLLIMPORT LPVOID dll_thread_tls_data(void);

#ifdef __cplusplus
}
#endif

#endif /* DLL_THREAD_H */
