/**
 * Use seccomp filters to restrict syscalls
 *
 * Linux examples: http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/samples/seccomp
 */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h> /* for offsetof */
#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* for memset */
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

#if defined __i386__
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#    define REG_RESULT REG_EAX
#    define REG_SYSCALL REG_EAX
#    define REG_ARG0 REG_EBX
#    define REG_ARG1 REG_ECX
#    define REG_ARG2 REG_EDX
#    define REG_ARG3 REG_ESI
#    define REG_ARG4 REG_EDI
#    define REG_ARG5 REG_EBP
#elif defined __x86_64__
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#    define REG_RESULT REG_RAX
#    define REG_SYSCALL REG_RAX
#    define REG_ARG0 REG_RDI
#    define REG_ARG1 REG_RSI
#    define REG_ARG2 REG_RDX
#    define REG_ARG3 REG_R10
#    define REG_ARG4 REG_R8
#    define REG_ARG5 REG_R9
#elif defined __arm__
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#else
#    error "Unsupported architecture"
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#    define SYSCALL_ARG_OFFSET 0
#elif __BYTE_ORDER == __BIG_ENDIAN
#    define SYSCALL_ARG_OFFSET 4
#else
#    error "Unknown endianness"
#endif

static bool install_syscall_filter(bool do_kill)
{
    struct sock_filter filter[] = {
        /* Check architecture (syscall convention), kill process if it fails */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

        /* Load the syscall number */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* Allow some syscalls (for exit, printf and sigreturn) */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#ifdef __NR_fstat64
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat64, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#ifdef __NR_mmap2
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap2, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigreturn, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        /* Allow writing only to stderr and stdout */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 5),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + SYSCALL_ARG_OFFSET),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDOUT_FILENO, 1, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDERR_FILENO, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

        /* Deny some other syscalls */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getcwd, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Trap getuid */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getpriority, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),

        /* Send SIGSYS to process */
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
    };
    const size_t filter_len = sizeof(filter) / sizeof(filter[0]);
    struct sock_fprog prog;

    if (!do_kill) {
        filter[filter_len - 1].k = SECCOMP_RET_TRAP;
    }

    prog.len = filter_len;
    prog.filter = filter;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl(NO_NEW_PRIVS)");
        return false;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        if (errno == EINVAL) {
            fprintf(stderr, "seccomp filters are not available\n");
        } else {
            perror("prctl(SECCOMP)");
        }
        return false;
    }
    return true;
}

static void sigsys_sigaction(int s, siginfo_t *info, void *context)
{
    ucontext_t *ctx = (ucontext_t *)context;
    assert(s == SIGSYS);
    assert(info != NULL && info->si_signo == SIGSYS);
    if (info->si_code != 1) {
        fprintf(stderr, "sigaction warning: unexpected info->si_signo, %d != 1.\n", info->si_signo);
    }
    if (info->si_arch != SECCOMP_AUDIT_ARCH) {
        fprintf(stderr,
                "sigaction error: unexpected info->si_arch, 0x%x != 0x%x.\n",
                info->si_arch, SECCOMP_AUDIT_ARCH);
        exit(1);
    }

    /* Emulate getpriority */
    if (info->si_syscall == __NR_getpriority && ctx) {
        greg_t syscall, arg0, arg1;
        syscall = ctx->uc_mcontext.gregs[REG_SYSCALL];
        assert(syscall == info->si_syscall);
        arg0 = ctx->uc_mcontext.gregs[REG_ARG0];
        arg1 = ctx->uc_mcontext.gregs[REG_ARG1];
        if (arg0 == PRIO_USER && arg1 == 0) {
            ctx->uc_mcontext.gregs[REG_RESULT] = 42;
            return;
        }
    }

    printf("Blocked syscall %d%s @%p\n", info->si_syscall,
           (info->si_syscall == __NR_uname) ? " (__NR_uname)" : "",
           info->si_call_addr);
    fflush(stdout);
    exit((info->si_syscall == __NR_uname) ? 0 : 1);
}

int main(int argc, char **argv)
{
    char cwd[4096], *buf;
    struct utsname name;
    struct sigaction act;
    sigset_t mask;
    int c;
    long prio;
    bool do_kill = false;

    while ((c = getopt(argc, argv, "hk")) != -1) {
        switch (c) {
            case 'h':
                printf("usage: seccomp [-h] [-k]\n");
                printf("optional arguments:\n");
                printf("  -h   show help and exit\n");
                printf("  -k   kill the program instead of handling a trap (write in audit log)\n");
                return 0;
            case 'k':
                do_kill = true;
                break;
            case '?':
                return 1;
        }
    }

    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = sigsys_sigaction;
    if (sigaction(SIGSYS, &act, NULL) == -1) {
        perror("sigaction");
        return 1;
    }
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
        perror("sigprocmask");
        return 1;
    }

    if (!install_syscall_filter(do_kill)) {
        return 1;
    }

    /* Do something allowed */
    printf("Hello, from a seccomp-filtered world!\n");
    fflush(stdout);

    /* Do something forbidden */
    buf = getcwd(cwd, sizeof(cwd));
    if (buf != NULL) {
        printf("getcwd didn't fail.\n");
    } else if (errno == EPERM) {
        printf("getcwd failed as expected.\n");
    } else {
        /* Don't use perror as it uses some denied syscalls */
        fprintf(stderr, "getcwd: %s\n", strerror(errno));
        return 1;
    }

    /* Use emulated getpriority */
    prio = syscall(__NR_getpriority, PRIO_USER, 0);
    if (prio == 42) {
        printf("getpriority has been successfully emulated.\n");
    } else {
        fprintf(stderr, "getpriority(user root): %s\n", strerror(errno));
        return 1;
    }

    /* Use yet another syscall to trigger SIGSYS */
    uname(&name);
    printf("Oh, I'm still alive! seccomp filters failed.\n");
    return 1;
}
