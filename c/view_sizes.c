/**
 * Print the size of the standard types, with the current processor architecture
 */

#include <stdio.h>

#if defined(__linux__) || defined(__unix__) || defined(__posix__)
#    include <sys/utsname.h>

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
    return 0;
}
