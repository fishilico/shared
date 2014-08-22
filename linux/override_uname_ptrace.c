/**
 * Override uname syscall using ptrace
 *
 * Example:
 *    $ ./override_uname_ptrace.bin -s S -n N -r R -v V -m M uname -a
 *    S N R V M GNU/Linux
 */
#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <asm/unistd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static struct utsname fake_uname;

#if defined __i386__
    #define REG_SYSCALL(regs) ((regs).orig_eax)
    #define REG_ARG0(regs) ((regs).ecx)
    #define REG_ARG1(regs) ((regs).edx)
    #define REG_ARG2(regs) ((regs).edi)
    #define REG_ARG3(regs) ((regs).esi)
    #define REG_ARG4(regs) ((regs).edi)
    #define REG_ARG5(regs) ((regs).ebp)
    #define REG_RESULT(regs) ((regs).eax)
#elif defined __x86_64__
    #define REG_SYSCALL(regs) ((regs).orig_rax)
    #define REG_ARG0(regs) ((regs).rdi)
    #define REG_ARG1(regs) ((regs).rsi)
    #define REG_ARG2(regs) ((regs).rdx)
    #define REG_ARG3(regs) ((regs).r10)
    #define REG_ARG4(regs) ((regs).r8)
    #define REG_ARG5(regs) ((regs).r9)
    #define REG_RESULT(regs) ((regs).rax)
#else
    #error "Unsupported architecture"
#endif

/**
 * Write the buffer content into into the target pid
 */
static int memcpy_to_pid(pid_t pid, void *dst, const void *src, size_t size)
{
    uint8_t *pdst = (uint8_t*)dst;
    const uint8_t *psrc = (uint8_t*)src;
    size_t i;

    /* ptrace works with words of size a pointer. */
    for (i = 0; i + sizeof(intptr_t) <= size; i += sizeof(intptr_t)) {
        intptr_t bytes;
        memcpy(&bytes, &psrc[i], sizeof(intptr_t));
        if (ptrace(PTRACE_POKEDATA, pid, &pdst[i], bytes) == -1) {
            perror("ptrace(POKEDATA)");
            return -1;
        }
    }

    /* Copy the remaining data */
    if (i < size) {
        intptr_t bytes;
        if (ptrace(PTRACE_PEEKDATA, pid, &pdst[i], &bytes) == -1) {
            perror("ptrace(PEEKDATA)");
            return -1;
        }
        assert(i + sizeof(intptr_t) > size);
        memcpy(&bytes, &psrc[i], size - i);
        if (ptrace(PTRACE_POKEDATA, pid, &pdst[i], bytes) == -1) {
            perror("ptrace(POKEDATA)");
            return -1;
        }
    }
    return 0;
}

static int handle_ptrace_events(pid_t child)
{
    pid_t pid;
    int status = 0, is_first = 1;
    long nsyscall;
    struct user_regs_struct regs;

    for (;;) {
        pid = waitpid(child, &status, WUNTRACED);
        if (pid == -1) {
            perror("waitpid");
            return EXIT_FAILURE;
        }
        assert(pid == child);
        if (WIFEXITED(status)) {
            status = WEXITSTATUS(status);
            return status;
        } else if (WIFSIGNALED(status)) {
            status = WTERMSIG(status);
            fprintf(stderr, "Child has been killed by signal %d.\n", status);
            kill(getpid(), status);
            return EXIT_FAILURE;
        } else if (WIFSTOPPED(status)) {
            status = WSTOPSIG(status);
            if (status == SIGSTOP) {
                /* The child suspended so suspend as well */
                kill(getpid(), SIGSTOP);
                kill(pid, SIGCONT);
            } else if ((status == SIGTRAP && is_first) ||
                       (status == (0x80 | SIGTRAP))) { /* PTRACE_O_TRACESYSGOOD options */
                /* This is the expected signal for ptrace! */
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                    perror("ptrace(GETREGS)");
                    return EXIT_FAILURE;
                }
                nsyscall = (long)REG_SYSCALL(regs);
                if (is_first) {
                    /* First syscall must be execve */
                    if (nsyscall != __NR_execve) {
                        fprintf(stderr, "Unexpected first syscall number: %ld != %d (execve).\n",
                            nsyscall, __NR_execve);
                        return EXIT_FAILURE;
                    }
                    /* Initialise ptrace options */
                    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
                               (PTRACE_O_TRACESYSGOOD |
                                PTRACE_O_TRACEFORK |
                                PTRACE_O_TRACEVFORK |
                                PTRACE_O_TRACECLONE)) == -1) {
                        perror("ptrace(PTRACE_SETOPTIONS)");
                    }
                    is_first = 0;
                }
                if (nsyscall == __NR_uname) {
                    /* Override user buffer */
                    /* FIXME: ptrace signals two times per syscall, on entry and exit.
                     *        Find out something to prevent poking buffer twice, and
                     *        which manages error codes.
                     */
                    if (memcpy_to_pid(pid, (void*)REG_ARG0(regs), &fake_uname, sizeof(fake_uname)) == -1) {
                        return EXIT_FAILURE;
                    }
                }
                if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                    perror("ptrace(CONT)");
                    return EXIT_FAILURE;
                }
            } else {
                fprintf(stderr, "Child has been stopped by unknown signal %d.\n", status);
                return EXIT_FAILURE;
            }
        } else {
            fprintf(stderr, "Child has reported an unknown state 0x%x.\n", status);
            return EXIT_FAILURE;
        }
    }
}

int main(int argc, char **argv)
{
    char **cmd;
    int c;
    pid_t child;

    /* Run real uname syscall before overwriting values */
    if (uname(&fake_uname) == -1) {
        perror("uname");
        return 1;
    }

    while ((c = getopt(argc, argv, "+hs:n:r:v:m:")) != -1) {
        switch (c) {
            case 'h':
                printf("Usage: %s [options] [--] command\n", argv[0]);
                printf("Options:\n");
                printf("    -s kernel-name\n");
                printf("    -n nodename\n");
                printf("    -r kernel-release\n");
                printf("    -v kernel-version\n");
                printf("    -m machine\n");
                return 0;
            case 's':
                strncpy(fake_uname.sysname, optarg, sizeof(fake_uname.sysname));
                fake_uname.sysname[sizeof(fake_uname.sysname) - 1] = 0;
                break;
            case 'n':
                strncpy(fake_uname.nodename, optarg, sizeof(fake_uname.nodename));
                fake_uname.nodename[sizeof(fake_uname.nodename) - 1] = 0;
                break;
            case 'r':
                strncpy(fake_uname.release, optarg, sizeof(fake_uname.release));
                fake_uname.release[sizeof(fake_uname.release) - 1] = 0;
                break;
            case 'v':
                strncpy(fake_uname.version, optarg, sizeof(fake_uname.version));
                fake_uname.version[sizeof(fake_uname.version) - 1] = 0;
                break;
            case 'm':
                strncpy(fake_uname.machine, optarg, sizeof(fake_uname.machine));
                fake_uname.machine[sizeof(fake_uname.machine) - 1] = 0;
                break;
            case '?':
                return 1;
        }
    }
    if (argc <= optind) {
        fprintf(stderr, "missing program in parameters\n");
        return 1;
    }
    cmd = argv + optind;

    /* Create a child */
    child = fork();
    if (child == (pid_t) -1) {
        perror("fork");
        return -1;
    } else if (child == 0) {
        /* Child: launch ptrace and run command */
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(TRACEME)");
            exit(EXIT_FAILURE);
        }
        execvp(*cmd, cmd);
        perror("execvp");
        exit(EXIT_FAILURE);
    }
    return handle_ptrace_events(child);
}
