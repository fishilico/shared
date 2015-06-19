/**
 * Measure the differences in timing when accessing cached data
 */
#if !defined(_GNU_SOURCE) && defined(__linux__)
#    define _GNU_SOURCE /* for sched_getaffinity, sched_setaffinity... */
#endif

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#    include <sched.h>
#    include <unistd.h>
#    include <sys/syscall.h>

static void fix_cpu(void)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == -1) {
        perror("sched_setaffinity(CPU 0)");
        /* Non-fatal error */
    }
}

static void dummy_syscall(void)
{
    syscall(__NR_read, STDIN_FILENO, NULL, 0);
}
#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
#    include <windows.h>

static void fix_cpu(void)
{
    if (!SetProcessAffinityMask(GetCurrentProcess(), 1)) {
        fprintf(stderr, "SetProcessAffinityMask(cpu 0): error %lu\n", GetLastError());
        /* Non-fatal error */
    }
}

static void dummy_syscall(void)
{
    LARGE_INTEGER perfCnt;

    QueryPerformanceCounter(&perfCnt);
}
#else
#    error Unknown target OS
#endif

/**
 * Read the content of the memory with an hardcoded ASM instruction
 */
#define load_memory(addr) \
    do { \
        uint32_t _read_val; \
        __asm__ volatile ("movl 0(%1), %0" : "=r" (_read_val) : "r" (addr)); \
    } while (0)

/**
 * Do an operation while reading the number of cycles taken for it
 */
static uint64_t measure_cycles_read(const volatile void *addr)
{
    uint32_t low1, high1, low2, high2;

    __asm__ volatile ("rdtsc" : "=a" (low1), "=d" (high1));
    load_memory(addr);
    __asm__ volatile ("rdtsc" : "=a" (low2), "=d" (high2));
    return (((uint64_t)(high2 - high1)) << 32) + low2 - low1;
}

int main(void)
{
    uint8_t *memory;
    unsigned int i;
    uint64_t cycles_sum;

    /* Ensure all the execution takes place on the same CPU thread */
    fix_cpu();

    /* Allocation some memory on the heap */
    memory = malloc(42);
    if (!memory) {
        fprintf(stderr, "malloc: cannot allocate memory\n");
        return 1;
    }

    /* Measure cache hit mean cycle number */
    cycles_sum = 0;
    for (i = 0; i < 10000; i++) {
        dummy_syscall();
        load_memory(memory);
        cycles_sum += measure_cycles_read(memory);
    }
    printf("Cache hit cycles (mean over %u): %" PRIu64 "\n", i, cycles_sum / i);

    /* Measure cache miss mean cycle number */
    cycles_sum = 0;
    for (i = 0; i < 10000; i++) {
        dummy_syscall(); /* Sync the pipeline with a syscall */
        load_memory(memory);
        __asm__ volatile ("clflush (%0)" : "+r" (memory));
        cycles_sum += measure_cycles_read(memory);
    }
    printf("Cache miss cycles (mean over %u): %" PRIu64 "\n", i, cycles_sum / i);

    free(memory);
    return 0;
}
