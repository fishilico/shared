/**
 * Print name and information about current kernel
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include <sys/utsname.h>
#include "nolibc-syscall-linux.h"

static ALWAYS_INLINE int _uname(struct utsname *name)
{
    return (int)syscall1(__NR_uname, name);
}

/**
 * Copy a size-bounded string, returning a pointer to its end
 */
static ALWAYS_INLINE char *stplcpy(char *dst, const char *src, size_t n)
{
    char c;
    do {
        c = *src++;
        *dst++ = c;
    } while (c && n-- > 0);
    return dst - 1;
}

void _start(void)
{
    struct utsname name;
    const char text_sysname[] = "sysname: ";
    const char text_nodename[] = "nodename: ";
    const char text_release[] = "release: ";
    const char text_version[] = "version: ";
    const char text_machine[] = "machine: ";
    const char text_domainname[] = "domainname: ";
    char buffer[sizeof(text_sysname) + sizeof(name.sysname) +
                sizeof(text_nodename) + sizeof(name.nodename) +
                sizeof(text_release) + sizeof(name.release) +
                sizeof(text_version) + sizeof(name.version) +
                sizeof(text_machine) + sizeof(name.machine) +
                sizeof(text_domainname) + sizeof(name.domainname) + 1];
    char *ptr;

    if (_uname(&name) < 0) {
        write_cstring_using_stack(2, "Error: uname failed\n");
        exit(1);
    }
    ptr = buffer;
    ptr = stplcpy(ptr, text_sysname, sizeof(text_sysname) - 1);
    ptr = stplcpy(ptr, name.sysname, sizeof(name.sysname));
    *ptr++ = '\n';
    ptr = stplcpy(ptr, text_nodename, sizeof(text_nodename) - 1);
    ptr = stplcpy(ptr, name.nodename, sizeof(name.nodename));
    *ptr++ = '\n';
    ptr = stplcpy(ptr, text_release, sizeof(text_release) - 1);
    ptr = stplcpy(ptr, name.release, sizeof(name.release));
    *ptr++ = '\n';
    ptr = stplcpy(ptr, text_version, sizeof(text_version) - 1);
    ptr = stplcpy(ptr, name.version, sizeof(name.version));
    *ptr++ = '\n';
    ptr = stplcpy(ptr, text_machine, sizeof(text_machine) - 1);
    ptr = stplcpy(ptr, name.machine, sizeof(name.machine));
    *ptr++ = '\n';
    ptr = stplcpy(ptr, text_domainname, sizeof(text_domainname) - 1);
    ptr = stplcpy(ptr, name.domainname, sizeof(name.domainname));
    *ptr++ = '\n';
    write_all(1, buffer, (size_t)(ptr - buffer));
    exit(0);
}
