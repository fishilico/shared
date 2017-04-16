/**
 * Override uname syscall using ptrace
 *
 * Example:
 *    $ ./override_uname_ptrace.bin -s S -n N -r R -v V -m M uname -a
 *    S N R V M GNU/Linux
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for pid_t, process_vm_writev */
#endif

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h> /* ptrace() */
#include <sys/syscall.h> /* __NR... */
#include <sys/uio.h>
#include <sys/user.h> /* struct user_regs_struct */
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static struct utsname fake_uname;

#if defined(__i386__)
#    define REG_SYSCALL(regs) ((regs).orig_eax)
#    define REG_ARG0(regs) ((regs).ebx)
#    define REG_ARG1(regs) ((regs).ecx)
#    define REG_ARG2(regs) ((regs).edx)
#    define REG_ARG3(regs) ((regs).esi)
#    define REG_ARG4(regs) ((regs).edi)
#    define REG_ARG5(regs) ((regs).ebp)
#    define REG_RESULT(regs) ((regs).eax)
typedef struct user_regs_struct user_regs_type;
#elif defined(__x86_64__)
#    define REG_SYSCALL(regs) ((regs).orig_rax)
#    define REG_ARG0(regs) ((regs).rdi)
#    define REG_ARG1(regs) ((regs).rsi)
#    define REG_ARG2(regs) ((regs).rdx)
#    define REG_ARG3(regs) ((regs).r10)
#    define REG_ARG4(regs) ((regs).r8)
#    define REG_ARG5(regs) ((regs).r9)
#    define REG_RESULT(regs) ((regs).rax)
typedef struct user_regs_struct user_regs_type;
#elif defined(__arm__)
/* As musl is missing asm/ptrace.h from Linux kernel, harcode offsets in
 * user_regs struct, like ARM_r* macros in
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/arm/include/uapi/asm/ptrace.h
 */
#    define REG_SYSCALL(regs) ((regs).uregs[7])
#    define REG_ARG0(regs) ((regs).uregs[17])
#    define REG_ARG1(regs) ((regs).uregs[1])
#    define REG_ARG2(regs) ((regs).uregs[2])
#    define REG_ARG3(regs) ((regs).uregs[3])
#    define REG_ARG4(regs) ((regs).uregs[4])
#    define REG_ARG5(regs) ((regs).uregs[5])
#    define REG_RESULT(regs) ((regs).uregs[0])
typedef struct user_regs user_regs_type;
#else
#    error "Unsupported architecture"
#endif

/* process_vm_writev has been introduced in Linux 3.2 and glibc 2.15. When
 * using old glibc with newer kernel header (e.g. Debian wheezy with glibc 2.13
 * and Linux headers 3.2), the wrapper is not defined properly.
 *
 * https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=78239589cd8c6667886b94c4db146109855f417a
 */
#if defined(__NR_process_vm_writev) && defined(__GNU_LIBRARY__) && ((__GLIBC__ << 16) + __GLIBC_MINOR__ < 0x2000f)
static ssize_t process_vm_writev(pid_t pid, const struct iovec *lvec, size_t liovcnt,
                                 const struct iovec *rvec, size_t riovcnt, unsigned long int flags)
{
    return (ssize_t)syscall(__NR_process_vm_writev, pid, lvec, liovcnt, rvec, riovcnt, flags);
}
#endif

/**
 * Write the buffer content into into the target pid
 */
static int memcpy_to_pid(pid_t pid, void *dst, const void *src, size_t size)
{
    uint8_t *pdst = (uint8_t *)dst;
    const uint8_t *psrc = (const uint8_t *)src;
    size_t i;

/* use process_vm_writev when available */
#ifdef __NR_process_vm_writev
    ssize_t written;
    struct iovec local_iov, remote_iov;

    /* try using process_vm_writev */
    memset(&local_iov, 0, sizeof(local_iov));
    /* work aroung clang's -Wcast-qual warning */
    local_iov.iov_base = (void *)(uintptr_t)src;
    local_iov.iov_len = size;
    memset(&remote_iov, 0, sizeof(remote_iov));
    remote_iov.iov_base = dst;
    remote_iov.iov_len = size;
    written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (written == -1) {
        /* Ignore errors due to old kernels */
        if (errno != ENOSYS) {
            perror("process_vm_writev");
        }
        /* Try ptrace... */
    } else if ((size_t)written != size) {
        fprintf(
            stderr, "process_vm_writev copied some data: %ld/%lu bytes\n",
            (long)written, (unsigned long)size);
        /* Try ptrace... */
    } else {
        /* Success */
        return 0;
    }
#endif

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
    int status = 0;
    long nsyscall;
    user_regs_type regs;

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
        } else if ((status & 0xff) == 0x7f /* WIFSTOPPED(status) */ ) {
            /*
             * Musl >= 0.9.12 defines WIFSTOPPED(s) as:
             *      ((short)((((s)&0xffff)*0x10001)>>8) > 0x7f00)
             * This causes an undefined behavior detected by clang on Alpine.
             * Hence hardcode WIFSTOPPED implementation instead.
             *
             * https://git.musl-libc.org/cgit/musl/commit/?id=41c632824c08ac2c9eea43b30d1b3515dd910df6
             */
            status = WSTOPSIG(status);
            if (status == SIGSTOP) {
                /* The child suspended so suspend as well */
                kill(getpid(), SIGSTOP);
                kill(pid, SIGCONT);
            } else if (status == SIGTRAP || status == (0x80 | SIGTRAP)) {
                /* This is the expected signal for ptrace */
                /* 0x80 is for PTRACE_O_TRACESYSGOOD options */
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                    perror("ptrace(GETREGS)");
                    return EXIT_FAILURE;
                }
                nsyscall = (long)REG_SYSCALL(regs);
                if (status == SIGTRAP) {
                    /* First syscall must be execve or restart_syscall.
                     * This may happen when running a new process
                     */
                    if (nsyscall != __NR_execve && nsyscall != __NR_restart_syscall) {
                        fprintf(stderr,
                                "Unexpected first syscall number: %ld != %d (execve).\n",
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
                }
                if (nsyscall == __NR_uname) {
                    /* Override user buffer */
                    /* FIXME: ptrace signals two times per syscall, on entry and exit.
                     *        Find out something to prevent poking buffer twice, and
                     *        which manages error codes.
                     */
                    if (memcpy_to_pid(pid, (void *)REG_ARG0(regs), &fake_uname, sizeof(fake_uname)) == -1) {
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

/* Use non-const strings for the sake of execvp */
static char cmd_uname[] = { 'u', 'n', 'a', 'm', 'e', '\0' };
static char cmd_a[] = { '-', 'a', '\0' };
static char *argv_uname_a[] = { cmd_uname, cmd_a, NULL };

int main(int argc, char **argv)
{
    char **cmd = argv_uname_a;
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
                printf("Usage: %s [options] [--] [command]\n", argv[0]);
                printf("Options:\n");
                printf("    -s kernel-name\n");
                printf("    -n nodename\n");
                printf("    -r kernel-release\n");
                printf("    -v kernel-version\n");
                printf("    -m machine\n");
                printf("If no command is supplied, 'uname' -a is used\n");
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

    if (argc > optind) {
        cmd = argv + optind;
    }

    /* Create a child */
    child = fork();
    if (child == (pid_t)-1) {
        perror("fork");
        return -1;
    } else if (child == 0) {
        /* Child: launch ptrace and run command */
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            if (errno == EPERM) {
                /* Docker filters this syscall in its default seccomp policy */
                printf("ptrace(TRACEME) is not permitted here.\n");
                exit(0);
            }
            perror("ptrace(TRACEME)");
            exit(EXIT_FAILURE);
        }
        execvp(*cmd, cmd);
        perror("execvp");
        exit(EXIT_FAILURE);
    }
    return handle_ptrace_events(child);
}
