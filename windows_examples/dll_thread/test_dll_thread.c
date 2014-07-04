/**
 * Test dll_thread.dll TLS interaction
 */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <windows.h>
#include "dll_thread.h"

#define NUM_THREADS 5

/* Entry Point des threads */
static DWORD WINAPI thread_main(LPVOID lpParam)
{
    int id = PtrToInt(lpParam);
    char *tls_buffer, *tls_buffer2;

    tls_buffer = dll_thread_tls_data();

    printf("[Thread #%d] Spawned yet another thread with TLS buffer @%"PRIxPTR"\n", id, (ULONG_PTR)tls_buffer);

    /* Write something in the TLS buffer */
    snprintf(tls_buffer, DLL_TLS_SIZE, "Hey! This is thread %d!", id);

    /* Give some time to other threads */
    Sleep(10);

    tls_buffer2 = dll_thread_tls_data();
    assert(tls_buffer == tls_buffer2);
    printf("[Thread #%d] Data after some sleep: %s\n", id, tls_buffer2);
    return 0;
}

int main()
{
    int i;
    HANDLE hTreads[NUM_THREADS];

    /* Unbufferize standard output to prevent caching issues */
    setvbuf(stdout, (char*)0, _IONBF, 0);

    hello_world();

    printf("Spawing %u threads.\n", NUM_THREADS);
    for (i = 0; i < NUM_THREADS; i++) {
        hTreads[i] = CreateThread(
            NULL,                   /* default security attributes */
            0,                      /* use default stack size */
            thread_main,            /* thread function name */
            IntToPtr(i + 1),        /* argument to thread function */
            0,                      /* use default creation flags */
            NULL);                  /* do not returns the thread identifier */
        if(hTreads[i] == NULL) {
            fprintf(stderr, "CreateThread failed for thread #%d: error code %lu\n", i + 1, GetLastError());
            return 1;
        }
    }
    WaitForMultipleObjects(NUM_THREADS, hTreads, TRUE, INFINITE);
    return 0;
}
