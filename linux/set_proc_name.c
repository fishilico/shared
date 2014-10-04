/**
 * Set the name of the current process
 *
 * This only changes the "comm" field, not argv[0] from API
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

static bool get_proc_name(char *buffer, size_t size)
{
    FILE *fcomm;
    size_t len;

    fcomm = fopen("/proc/self/comm", "r");
    if (!fcomm) {
        perror("fopen(/proc/self/comm)");
        return false;
    }

    if (!fgets(buffer, (int)size, fcomm)) {
        fprintf(stderr, "Unable to read /proc/self/comm\n");
        fclose(fcomm);
        return false;
    }
    fclose(fcomm);

    len = strlen(buffer);
    assert(len > 0 && len < size);
    if (buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    return true;
}

int main(void)
{
    const char *new_name = "Hello, world!";
    char buffer[4096];

    if (!get_proc_name(buffer, sizeof(buffer))) {
        return 1;
    }
    printf("Old name: %s\n", buffer);

    if (prctl(PR_SET_NAME, new_name) == -1) {
        perror("prctl");
        return 1;
    }

    if (!get_proc_name(buffer, sizeof(buffer))) {
        return 1;
    }
    printf("New name: %s\n", buffer);

    if (strcmp(new_name, buffer)) {
        printf("Error: expected name was %s\n", new_name);
        return 1;
    }
    return 0;
}
