/**
 * Print the size of the standard types, with the current processor architecture
 */
#include <stddef.h>
#include <stdio.h>

static int exitcode = 0;

#if defined(__linux__) || defined(__unix__) || defined(__posix__)
#    include <sys/types.h>
#    include <sys/utsname.h>

#    define IS_SIZE_T_COMPATIBLE_WITH_ULONG (sizeof(size_t) == 8 ? 1 : 0)

static void print_machine(void)
{
    struct utsname utsname;
    if (uname(&utsname) == 0) {
        printf("Machine: %s\n", utsname.machine);
    } else {
        perror("uname");
    }
}
#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
#    include <windows.h>

#    define IS_SIZE_T_COMPATIBLE_WITH_ULONG 0

static void print_machine(void)
{
    SYSTEM_INFO siSysInfo;
    const char *machine;
    GetSystemInfo(&siSysInfo);
    switch (siSysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            machine = "x86_64";
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            machine = "arm";
            break;
        case PROCESSOR_ARCHITECTURE_IA64:
            machine = "ia64";
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            machine = "x86";
            break;
        case PROCESSOR_ARCHITECTURE_UNKNOWN:
            machine = "unknown";
            break;
        default:
            machine = "?? (not implemented value)";
    }
    printf("Machine: %s\n", machine);
}
#else
#    warning Unsupported target OS
#    define print_machine() do {} while(0)
#endif

static void _print_type_size(const char *name, size_t size)
{
    printf(" * sizeof(%11s) = %2lu %s (%3lu bits)\n",
           name, (unsigned long)size, (size == 1) ? "byte " : "bytes",
           (unsigned long)size * 8);
}

#define print_type_size(type) _print_type_size(#type, sizeof(type))

static void _print_compatibility(const char *t1, const char *t2, int exp,
                                 int res1, int res2)
{
    /* Verify that __builtin_types_compatible_p() is commutative */
    if (exp != res1) {
        printf(" ! %15s : %-15s = %d instead of expected %d\n", t1, t2, res1, exp);
        exitcode = 1;
    } else if (exp != res2) {
        printf(" ! %15s : %-15s = %d instead of expected %d\n", t2, t1, res2, exp);
        exitcode = 1;
    } else {
        printf(" * %15s : %-15s = %d\n", t1, t2, exp);
    }
}

#define print_compatibility(t1, t2, exp) \
    _print_compatibility(#t1, #t2, (exp), \
        __builtin_types_compatible_p(t1, t2), \
        __builtin_types_compatible_p(t2, t1))

int main(void)
{
    print_machine();
    printf("Integer types:\n");
    print_type_size(char);
    print_type_size(short);
    print_type_size(int);
    print_type_size(long);
    print_type_size(long long);
    printf("\n");
    print_type_size(size_t);
    printf("\nFloat types:\n");
    print_type_size(float);
    print_type_size(double);
    print_type_size(long double);
    printf("\nPointer types:\n");
    print_type_size(void *);
    print_type_size(int *);

    printf("\nType compatibilities:\n");
    print_compatibility(char, int, 0);
    print_compatibility(short, int, 0);
    print_compatibility(long, int, 0);
    print_compatibility(const int, int, 1);
    print_compatibility(unsigned int, int, 0);
    print_compatibility(long, long long, 0);
    print_compatibility(long, ssize_t, IS_SIZE_T_COMPATIBLE_WITH_ULONG);
    print_compatibility(long, size_t, 0);
    print_compatibility(unsigned long, size_t, IS_SIZE_T_COMPATIBLE_WITH_ULONG);
    print_compatibility(const char *, char *, 0);
    print_compatibility(unsigned char *, char *, 0);
    print_compatibility(void *, char *, 0);
    print_compatibility(char[], char *, 0);
    print_compatibility(char[1], char *, 0);
    print_compatibility(char[2], char[1], 0);

    return exitcode;
}
