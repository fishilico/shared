/**
 * Read and write from an allocated memory with no normal access
 */
#include "recover_segfault.h"

#include <stdio.h>
#include <string.h>

static uint8_t noaccess_data[4096];

#if defined(__linux__) || defined(__unix__) || defined(__posix__)
#    include <sys/mman.h>

static void *alloc_noaccess_page(size_t size, unsigned char mark)
{
    void *ptr;

    ptr = mmap(NULL, size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    if (!ptr) {
        fprintf(stderr, "What? mmap just managed to allocate the NULL page. Must be kidding...");
        munmap(ptr, size);
        return NULL;
    }
    memset(ptr, mark, size);
    if (mprotect(ptr, size, PROT_NONE) < 0) {
        perror("mprotect");
        munmap(ptr, size);
        return NULL;
    }
    return ptr;
}

static void free_noaccess_page(void *ptr, size_t size)
{
    if (ptr) {
        munmap(ptr, size);
    }
}
#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)

static void *alloc_noaccess_page(size_t size, unsigned char mark)
{
    void *ptr;
    DWORD dwOldProtect;

    ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        fprintf(stderr, "VirtualAlloc: error %lu\n", GetLastError());
        return NULL;
    }
    memset(ptr, mark, size);
    if (!VirtualProtect(ptr, size, PAGE_NOACCESS, &dwOldProtect)) {
        fprintf(stderr, "VirtualProtect: error %lu\n", GetLastError());
        VirtualFree(ptr, 0, MEM_RELEASE);
        return NULL;
    }
    return ptr;
}

static void free_noaccess_page(void *ptr, size_t size __attribute__((unused)))
{
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}
#else
#    error "Unknown target OS"
#endif

static int use_noaccess(void *noaccess_ptr)
{
    uint8_t *ptr = (uint8_t *)noaccess_ptr, c;

    /* Read a byte */
    c = ptr[42];
    if (c == 0xba) {
        printf("[-] Unexpectedly managed to read the mark from the no-access data: 0x%02x\n", c);
        return 1;
    } else if (c) {
        printf("[?] Unexpected value read from the no-access data: 0x%02x\n", c);
        return 1;
    }
    printf("[+] Successfully read a byte from the no-access data\n");
    return 0;
}

int main(void)
{
    void *noaccess_ptr;
    struct segfault_memcontent memory;
    int retval;

    noaccess_ptr = alloc_noaccess_page(sizeof(noaccess_data), 0xba);
    if (!noaccess_ptr) {
        return 1;
    }
    printf("[ ] No-access memory allocated at %p\n", noaccess_ptr);

    memory.addr = (uintptr_t)noaccess_ptr;
    memory.data = noaccess_data;
    memory.size = sizeof(noaccess_data);

    retval = run_with_segfault_handler(&memory, 1, use_noaccess, noaccess_ptr);

    free_noaccess_page(noaccess_ptr, sizeof(noaccess_data));
    return retval;
}
