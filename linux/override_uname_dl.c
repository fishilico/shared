/**
 * Override uname return value with environment variables
 */
#include <dlfcn.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#if __GNUC__ >= 4
    #define EXPORT_FUNC __attribute__((visibility("default")))
#else
    #define EXPORT_FUNC
#endif

typedef int (*uname_t)(struct utsname * buf);

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

    real_uname = (uname_t)(intptr_t)dlsym(RTLD_NEXT, __FUNCTION__);
    if (!real_uname) {
        fprintf(stderr, "dlsym(%s): %s", __FUNCTION__, dlerror());
        exit(EXIT_FAILURE);
    }
    ret = real_uname(buf);
    if (buf) {
        fake_with_env(buf->sysname, sizeof(buf->sysname), "FAKEUNAME_S");
        fake_with_env(buf->nodename, sizeof(buf->nodename), "FAKEUNAME_N");
        fake_with_env(buf->release, sizeof(buf->release), "FAKEUNAME_R");
        fake_with_env(buf->version, sizeof(buf->version), "FAKEUNAME_V");
        fake_with_env(buf->machine,sizeof(buf->machine),  "FAKEUNAME_M");
    }
    return ret;
}
