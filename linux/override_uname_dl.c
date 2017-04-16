/**
 * Override uname return value with environment variables
 *
 * Simple usage example:
 *
 *     $ export FAKEUNAME_S=FakeLinux
 *     $ export LD_PRELOAD=./override_uname_dl.so
 *     $ uname -s
 *     FakeLinux
 *
 * Usage with gdb:
 *
 *      $ gdb --args uname -s
 *      (gdb) set environment FAKEUNAME_S=FakeLinux
 *      (gdb) set environment LD_PRELOAD=./override_uname_dl.so
 *      (gdb) run
 *      Starting program: /usr/bin/uname -s
 *      FakeLinux
 *      [Inferior 1 (process 1042) exited normally]
 *      (gdb) quit
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for RTLD_NEXT */
#endif

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#if __GNUC__ >= 4
#    define EXPORT_FUNC __attribute__((visibility("default")))
#else
#    define EXPORT_FUNC
#endif

typedef int (*uname_t) (struct utsname * buf);

/**
 * Replace a string with an environment variable, if provided
 */
static void fake_with_env(char *value, size_t size, const char *env_name)
{
    char *env_value;
    env_value = getenv(env_name);
    if (env_value) {
        memset(value, 0, size);
        strncpy(value, env_value, size - 1);
    }
}

int EXPORT_FUNC uname(struct utsname *buf)
{
    int ret;
    uname_t real_uname;

    real_uname = (uname_t)(intptr_t)(dlsym(RTLD_NEXT, "uname"));
    if (!real_uname) {
        fprintf(stderr, "dlsym(uname): %s", dlerror());
        exit(EXIT_FAILURE);
    }
    ret = real_uname(buf);
    if (buf) {
        fake_with_env(buf->sysname, sizeof(buf->sysname), "FAKEUNAME_S");
        fake_with_env(buf->nodename, sizeof(buf->nodename), "FAKEUNAME_N");
        fake_with_env(buf->release, sizeof(buf->release), "FAKEUNAME_R");
        fake_with_env(buf->version, sizeof(buf->version), "FAKEUNAME_V");
        fake_with_env(buf->machine, sizeof(buf->machine), "FAKEUNAME_M");
    }
    return ret;
}

/**
 * Print a message if no environment variable is set
 */
static void __attribute__ ((constructor)) init(int argc, char **argv, char **env)
{
    int i;

    for (i = 0; env[i]; i++) {
        if (!strncmp(env[i], "FAKEUNAME_", sizeof("FAKEUNAME_") - 1)) {
            return;
        }
    }
    if (argc >= 1) {
        fprintf(stderr, "Running '%s' without changing anything.\n", argv[0]);
    }
}
