/**
 * Example program to show how to migrate between several CPUs on a system
 */
#include <assert.h>
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#if !defined CPU_ALLOC && !defined CPU_ZERO_S
/* Define the _S API from the older one */
#define CPU_ISSET_S(cpu, setsize, set) CPU_ISSET((cpu), (set))
#define CPU_SET_S(cpu, setsize, set) do {(void)setsize; CPU_SET((cpu), (set));} while (0)
#define CPU_CLR_S(cpu, setsize, set) do {(void)setsize; CPU_CLR((cpu), (set));} while (0)

#define CPU_ZERO_S(setsize, set) CPU_ZERO((set))
#define CPU_COUNT_S(setsize, set) _cpu_count_s((setsize), (set))
static int _cpu_count_s(size_t setsize, cpu_set_t *set)
{
    int count = 0;
    size_t i;
    assert(setsize == sizeof(set->__bits));
    for (i = 0; i < sizeof(set->__bits)/sizeof(set->__bits[0]); i++) {
        __cpu_mask b;
        for (b = set->__bits[i]; b; b >>= 1) {
            if (b & 1) {
                count++;
            }
        }
    }
    return count;
}

#define CPU_AND_S(setsize, destset, srcset1, srcset2) \
    do { \
        size_t i; \
        assert((setsize) == sizeof((destset)->__bits)); \
        for (i = 0; i < sizeof((destset)->__bits)/sizeof((destset)->__bits[0]); i++) { \
            (destset)->__bits[i] = (srcset1)->__bits[i] & (srcset2)->__bits[i]; \
        } \
    } while (0)

#define CPU_EQUAL_S(setsize, cpusetp1, cpusetp2) (!memcmp((cpusetp1), (cpusetp2), (setsize)))

#define CPU_ALLOC_SIZE(count) ((void)(count), sizeof(cpu_set_t))
#define CPU_ALLOC(count) malloc(CPU_ALLOC_SIZE((count)))
#define CPU_FREE(set) free((set))

#include <sys/syscall.h>
#include <unistd.h>
#define sched_getcpu() sched_getcpu_from_syscall()
int sched_getcpu_from_syscall() {
    unsigned int cpu = 0;
    if (syscall(__NR_getcpu, &cpu, NULL, NULL) == -1) {
        return -1;
    }
    assert(cpu <= INT_MAX);
    return (int)cpu;
}
#endif

/**
 * List available CPUs with sched_getaffinity
 * Fill set if not NULL and return the number of CPUs, or 0 on error.
 */
static unsigned long list_cpus_sched_affinity(cpu_set_t *set, size_t setsize)
{
    unsigned long cpu_num;
    int i, count;
    cpu_set_t local_set;
    /* Use a local variable if only the maximum of CPU IDs need to be retrieved */
    if (!set) {
        set = &local_set;
        setsize = sizeof(local_set);
        CPU_ZERO_S(setsize, set);
    }
    if (sched_getaffinity(0, setsize, set) == -1) {
        perror("sched_getaffinity");
        return 0;
    }
    count = CPU_COUNT_S(setsize, set);
    for (i = 0, cpu_num = 0; i < count && cpu_num <= 8 * setsize; cpu_num++) {
        if (CPU_ISSET_S(cpu_num, setsize, set)) {
            i++;
        }
    }
    return cpu_num;
}

/**
 * List available CPUs with /proc/stat
 * Fill set if not NULL and return the number of CPUs, or 0 on error.
 */
static unsigned long list_cpus_proc_stat(cpu_set_t *set, size_t setsize)
{
    unsigned long cpu_max = 0;
    FILE *file;
    char buffer[4096];

    file = fopen("/proc/stat", "r");
    if (!file) {
        perror("fopen(/proc/stat)");
        return 0;
    }
    while (fgets(buffer, sizeof(buffer), file)) {
        if (!strncmp(buffer, "cpu", 3) && buffer[3] >= '0' && buffer[3] <= '9') {
            unsigned long cpu;
            char *endptr = buffer + 3;
            cpu = strtoul(endptr, &endptr, 10);
            if (*endptr != ' ') {
                fprintf(stderr, "strtoul: failed to parse line: %s\n", buffer);
                continue;
            }
            if (cpu_max < cpu) {
                cpu_max = cpu;
            }
            if (set) {
                CPU_SET_S(cpu, setsize, set);
            }
        }
    }
    fclose(file);
    return cpu_max + 1;
}

/**
 * List available CPUs with /sys/devices/system/cpu/
 * Fill set if not NULL and return the number of CPUs, or 0 on error.
 */
static unsigned long list_cpus_sys_dev(cpu_set_t *set, size_t setsize)
{
    unsigned long cpu_max = 0;
    DIR *dir;
    struct dirent *dent;

    dir = opendir("/sys/devices/system/cpu");
    if (!dir) {
        perror("opendir(/sys/devices/system/cpu)");
        return 0;
    }
    while ((dent = readdir(dir)) != NULL) {
        if (!strncmp(dent->d_name, "cpu", 3) && dent->d_name[3] >= '0' && dent->d_name[3] <= '9') {
            unsigned long cpu;
            char *endptr = dent->d_name + 3;
            cpu = strtoul(endptr, &endptr, 10);
            if (*endptr) {
                fprintf(stderr, "strtoul: failed to parse %s\n", dent->d_name);
                continue;
            }
            if (cpu_max < cpu) {
                cpu_max = cpu;
            }
            if (set) {
                CPU_SET_S(cpu, setsize, set);
            }
        }
    }
    closedir(dir);
    return cpu_max + 1;
}

/**
 * Migrate the current thread to the given CPU
 */
static bool migrate_to_cpu(unsigned long cpu, unsigned long cpu_num)
{
    cpu_set_t *set;
    size_t setsize;

    set = CPU_ALLOC(cpu_num);
    assert(set);
    setsize = CPU_ALLOC_SIZE(cpu_num);
    CPU_ZERO_S(setsize, set);
    CPU_SET_S(cpu, setsize, set);
    if (sched_setaffinity(0, setsize, set) == -1) {
        perror("sched_setaffinity");
        CPU_FREE(set);
        return false;
    }
    CPU_FREE(set);
    return true;
}

#if defined __x86_64__ || defined __i386__
/**
 * Read the Time Stamp Counter of the current CPU
 */
static uint64_t rdtsc(void)
{
    unsigned int low, high;
    __asm__ volatile ("rdtsc" : "=a" (low), "=d" (high));
    return low | ((uint64_t)high) << 32;
}
#define HAVE_RDTSC 1
#else
#define HAVE_RDTSC 0
#endif

int main(int argc, char **argv)
{
    unsigned long cpu_num, cpu_num1, cpu_num2, cpu_num3, cpu_index;
    cpu_set_t *set, *set1, *set2, *set3;
    size_t setsize;
    double duration = 0;

    /* Gather number of CPUs */
    cpu_num1 = list_cpus_sched_affinity(NULL, 0);
    cpu_num2 = list_cpus_proc_stat(NULL, 0);
    cpu_num3 = list_cpus_sys_dev(NULL, 0);
    cpu_num = (cpu_num1 > cpu_num2) ? cpu_num1 : cpu_num2;
    cpu_num = (cpu_num > cpu_num3) ? cpu_num : cpu_num3;
    printf("Found %lu CPUs\n", cpu_num);
    if (cpu_num1 && cpu_num1 != cpu_num) {
        printf( "Warning: sched_getaffinity reported a bad number of CPUs: %lu\n", cpu_num1);
    }
    if (cpu_num2 && cpu_num2 != cpu_num) {
        printf("Warning: /proc/stat contained a bad number of CPUs: %lu\n", cpu_num2);
    }
    if (cpu_num3 && cpu_num3 != cpu_num) {
        printf("Warning: /sys/devices/system/cpu contained a bad number of CPUs: %lu\n", cpu_num3);
    }

    /* Allocate enough cpu_set_t structures */
    set = CPU_ALLOC(cpu_num);
    set1 = CPU_ALLOC(cpu_num);
    set2 = CPU_ALLOC(cpu_num);
    set3 = CPU_ALLOC(cpu_num);
    assert(set && set1 && set2 && set3);
    setsize = CPU_ALLOC_SIZE(cpu_num);
    CPU_ZERO_S(setsize, set1);
    CPU_ZERO_S(setsize, set2);
    CPU_ZERO_S(setsize, set3);

    /* List CPU IDs */
    list_cpus_sched_affinity(set1, setsize);
    list_cpus_proc_stat(set2, setsize);
    list_cpus_sys_dev(set3, setsize);
    if (!CPU_EQUAL_S(setsize, set1, set2)) {
        printf("Warning: list of CPU IDs reported by sched_getaffinity and /proc/stat differ\n");
    }
    if (!CPU_EQUAL_S(setsize, set1, set3)) {
        printf("Warning: list of CPU IDs reported by sched_getaffinity and /sys/devices/system/cpu differ\n");
    }
    if (!CPU_EQUAL_S(setsize, set2, set3)) {
        printf("Warning: list of CPU IDs reported by /proc/stat and /sys/devices/system/cpu differ\n");
    }
    CPU_AND_S(setsize, set, set1, set2);
    CPU_AND_S(setsize, set, set, set3);
    CPU_FREE(set1);
    CPU_FREE(set2);
    CPU_FREE(set3);

    /* Do a busy wait in a loop on each CPU if a number of seconds is given */
    if (argc >= 2 && argv[1][0] >= '0' && argv[1][0] <= '9') {
        char *endptr = argv[1];
        duration = strtod(endptr, &endptr);
        if (*endptr) {
            fprintf(stderr, "strtod: failed to parse %s\n", argv[1]);
            return 1;
        }
    }


    /* Migrate to every CPU */
    for (cpu_index = 0; cpu_index < cpu_num; cpu_index++) {
        int cpu;
        if (!CPU_ISSET_S(cpu_index, setsize, set)) {
            continue;
        }
        if (!migrate_to_cpu(cpu_index, cpu_num)) {
            return 1;
        }
        cpu = sched_getcpu();
        if (cpu == -1) {
            perror("sched_getcpu");
            return 1;
        }
        assert(cpu >= 0);
        if ((unsigned long)cpu == cpu_index) {
#if HAVE_RDTSC
            printf("Migrated to CPU %d, TSC=%"PRIu64"\n", cpu, rdtsc());
#else
            printf("Migrated to CPU %d\n", cpu);
#endif
        } else {
            printf("Failed to migrated to CPU %lu, still on %d\n", cpu_index, cpu);
        }

        /* Do a busy wait in a loop if a number of seconds is given */
        if (duration) {
            time_t start_time, now;
            if (time(&start_time) == (time_t) -1) {
                perror("time");
                return 1;
            }
            printf("... active loop for %.3lf seconds\n", duration);
            do {
                if (time(&now) == (time_t) -1) {
                    perror("time");
                    return 1;
                }
            } while (difftime(now, start_time) < duration);
        }
    }
    CPU_FREE(set);
    return 0;
}
