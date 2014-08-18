/**
 * Use eventfd with child processes
 */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define NUM_CHILDS 7

int main(void)
{
    int efd;
    pid_t pids[NUM_CHILDS];
    unsigned int i;
    eventfd_t value;

    /* Create a new eventfd */
    efd = eventfd(0, EFD_CLOEXEC);
    if (efd == -1) {
        perror("eventfd");
        return 1;
    }

    /* Fork processes which writes to the event fd to increment its value */
    for (i = 0; i < NUM_CHILDS; i++) {
        pids[i] = fork();
        if (pids[i] == -1) {
            perror("fork");
            return 1;
        } else if (pids[i] == 0) {
            unsigned int val = 3 + i;
            printf("Process %u (PID %u): write %u to eventfd.\n", i, getpid(), val);
            if (eventfd_write(efd, val) == -1) {
                perror("eventfd_write");
                exit(EXIT_FAILURE);
            }
            exit(EXIT_SUCCESS);
        }
    }

    /* Wait for every child */
    for (i = 0; i < NUM_CHILDS; i++) {
        int status = 0;
        pid_t pid;
        for (;;) {
            printf("waiting %d...\n", i);
            pid = waitpid(pids[i], &status, WUNTRACED);
            if (pid == -1) {
                perror("waitpid");
                return 1;
            }
            assert(pid == pids[i]);
            if (WIFSTOPPED(status)) {
                /* The child suspended so suspend as well */
                kill(getpid(), SIGSTOP);
                kill(pid, SIGCONT);
            } else {
                break;
            }
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
            fprintf(stderr, "Child %u failed (PID %u), exiting.\n", i, pid);
            if (WIFSIGNALED(status)) {
                kill(getpid(), WTERMSIG(status));
            }
            return status;
        }
    }

    /* Read eventfd */
    if (eventfd_read(efd, &value) == -1) {
        perror("eventfd_read");
        return 1;
    }
    printf("Final value: %"PRIu64"\n", value);

    close(efd);
    return 0;
}
