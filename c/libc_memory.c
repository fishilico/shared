/**
 * Analyze how the libc manages the memory (metadata of allocated blocks, free
 * blocks, etc.)
 *
 * Documentation:
 * * https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c
 *   glibc malloc/free implementations
 * * http://git.musl-libc.org/cgit/musl/tree/src/malloc/malloc.c
 *   musl malloc/free implementations
 * * https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/heap.c
 *   Wine RtlAllocateHeap/RtlFreeHeap implementations
 * * ftp://g.oswego.edu/pub/misc/malloc.c
 *   dlmalloc, Doug Lea malloc
 * * https://github.com/jemalloc/jemalloc
 *   jemalloc, Jason Evans malloc
 */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Show the metadata allocated right before malloc blocks
 *
 * Size of metadata:
 * * x86_32:
 *   - glibc: 8 bytes
 *   - Windows: 8 bytes
 * * x86_64:
 *   - glibc: 16 bytes (can be caused by alignment constraints)
 *   - glibc+valgrind: 64 bytes
 *   - musl libc: 32 bytes
 *   - Windows: 16 bytes (can be caused by alignment constraints)
 */
static void show_malloc_metadata(void)
{
    const unsigned int allocsize = 40960;
    void *p1, *p2;
    uintptr_t addr_low, addr_high;
    unsigned int alloc_metasize, iline, icol;
    const uint8_t *line8;
    const uint32_t *line32;

    /* Allocate two 40 Kio blocks */
    p1 = malloc(allocsize);
    p2 = malloc(allocsize);
    if (!p1 || !p2) {
        fprintf(stderr, "Error while allocating 2x%u bytes.\n", allocsize);
        free(p1);
        free(p2);
        exit(1);
    }
    printf("Allocated 0x%x bytes in %p and %p\n", allocsize, p1, p2);

    addr_low = (uintptr_t)p1;
    addr_high = (uintptr_t)p2;
    if (addr_high < addr_low) {
        addr_low = (uintptr_t)p2;
        addr_high = (uintptr_t)p1;
    }
    printf("Difference: %" PRIdPTR " = %u + %" PRIdPTR "\n",
           addr_high - addr_low, allocsize, addr_high - addr_low - allocsize);
    assert(addr_low + allocsize <= addr_high);

    if (addr_low + allocsize + 1024 <= addr_high) {
        printf("... interval too large to be contiguous blocks :(\n");
        goto cleanup;
    }

    printf("Content of malloc metadata:\n");
    alloc_metasize = (unsigned int)(addr_high - addr_low - allocsize);
    for (iline = 0; iline < alloc_metasize; iline += 8) {
        line8 = (const uint8_t *)(addr_low + allocsize + iline);
        line32 = (const uint32_t *)(addr_low + allocsize + iline);
        printf("  %04x:", iline);
        for (icol = 0; icol < 8; icol++) {
            if (iline + icol < alloc_metasize) {
                printf(" %02x", line8[icol]);
            } else {
                printf("   ");
            }
        }
        printf("  0x%08x", line32[0]);
        if (4 < alloc_metasize) {
            printf(" 0x%08x", line32[1]);
        }
        printf("\n");
    }
    printf("\n");

cleanup:
    free(p1);
    free(p2);
}

/**
 * Dump the content of the free chunk at the specified address.
 * Usually the structures contains:
 * * the size of the chunk, possibly with the less significant bit set (PREV_INUSE)
 * * pointers to a double-linked ("bk" to previous and "fd" to next, back & forward)
 */
static void dump_freechunk_content(const void *freeptr, unsigned int size)
{
    uintptr_t freeaddr = (uintptr_t)freeptr;
    unsigned int iline, icol, num_zerolines = 0;
    const uint8_t *line8;
    const uint32_t *line32;

    for (iline = 0; iline < size; iline += 8) {
        line8 = (const uint8_t *)(freeaddr + iline);
        line32 = (const uint32_t *)(freeaddr + iline);

        if (num_zerolines > 0) {
            if (!line32[0] && !line32[1]) {
                num_zerolines += 1;
                continue;
            }
            /* Non-zero line after several zero lines */
            if (num_zerolines > 1) {
                printf("  *\n");
            }
            num_zerolines = 0;
        } else if (!line32[0] && !line32[1]) {
            num_zerolines = 1;
            continue;
        }

        printf("  %04x:", iline);
        for (icol = 0; icol < 8; icol++) {
            if (iline + icol < size) {
                printf(" %02x", line8[icol]);
            } else {
                printf("   ");
            }
        }
        if (sizeof(void *) == 8) {
            printf("  0x%016" PRIx64, *(uint64_t *)(freeaddr + iline));
        } else {
            printf("  0x%08x 0x%08x", line32[0], line32[1]);
        }
        printf("\n");
    }
    printf("\n");
}

/**
 * Show the metadata of free chunks
 */
static void show_free_metadata(void)
{
#define NUM_ALLOCATED_BLOCKS 5
    const unsigned int allocsize = 4096;
    void *ptr[NUM_ALLOCATED_BLOCKS];
    uintptr_t addr[NUM_ALLOCATED_BLOCKS];
    unsigned int i, total_size;
    void *freechunk1 = NULL, *freechunk3 = NULL;

    /* Allocate some blocks in hope they are contiguous */
    for (i = 0; i < NUM_ALLOCATED_BLOCKS; i++) {
        ptr[i] = malloc(allocsize);
        if (!ptr[i]) {
            fprintf(stderr, "Error while allocating %u bytes.\n", allocsize);
            while (i > 0) {
                free(ptr[--i]);
            }
            exit(1);
        }
        memset(ptr[i], 0, allocsize);
        addr[i] = (uintptr_t)ptr[i];
    }
    printf("Allocated %u 0x%x-byte block in:\n", NUM_ALLOCATED_BLOCKS, allocsize);
    for (i = 0; i < NUM_ALLOCATED_BLOCKS; i++) {
        printf("  %p\n", ptr[i]);
    }

    /* Check that the blocks are contiguous */
    for (i = 0; i < NUM_ALLOCATED_BLOCKS - 1; i++) {
        if (addr[i] > addr[i + 1]) {
            printf("... blocks are not ordered :(\n");
            goto cleanup;
        }
        assert(addr[i] + allocsize < addr[i + 1]);
        if (addr[i] + allocsize + 1024 <= addr[i + 1]) {
            printf("... interval too large to be contiguous blocks :(\n");
            goto cleanup;
        }
        if (addr[i + 1] - addr[i] != addr[1] - addr[0]) {
            printf("... interval between blocks is variable :(\n");
            goto cleanup;
        }
    }
    total_size = (unsigned int)(addr[1] - addr[0]);

    /* Allocate blocks which will contain the content of the freed chunks */
    freechunk1 = malloc(total_size);
    freechunk3 = malloc(total_size);
    if (!freechunk1 || !freechunk3) {
        fprintf(stderr, "Error while allocating 2x%u bytes.\n", total_size);
        for (i = 0; i < NUM_ALLOCATED_BLOCKS; i++) {
            free(ptr[i]);
        }
        exit(1);
    }

    /* Free the second and the forth blocks and copy their contents before
     * internal libc functions reuse them (like printf on Windows).
     */
    free(ptr[1]);
    free(ptr[3]);
    ptr[1] = ptr[3] = NULL;
    memcpy(freechunk1, (const void *)(addr[0] + allocsize), total_size);
    memcpy(freechunk3, (const void *)(addr[2] + allocsize), total_size);

    /* Show the contents of the data */
    printf("Content of the second freed block at %p:\n", (void *)(addr[0] + allocsize));
    dump_freechunk_content(freechunk1, total_size);

    printf("Content of the forth freed block at %p:\n", (void *)(addr[2] + allocsize));
    dump_freechunk_content(freechunk3, total_size);

cleanup:
    free(freechunk1);
    free(freechunk3);
    for (i = 0; i < NUM_ALLOCATED_BLOCKS; i++) {
        free(ptr[i]);
    }
}

int main(void)
{
    show_malloc_metadata();
    show_free_metadata();
    return 0;
}
