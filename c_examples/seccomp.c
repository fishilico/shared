/**
 * Use seccomp filters to restrict syscalls
 */
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h> /* for offsetof */
#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* for memset */
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

#if defined __i386__
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined __x86_64__
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined __arm__
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#else
    #error Unsupported architecture
#endif

static bool install_syscall_filter(void)
{
    struct sock_filter filter[] = {
        /* Check architecture (syscall convention), kill process if it fails */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
        /* Load the syscall number */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* Allow some syscalls (for exit and printf) */
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fstat, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        /* Deny some other syscalls */
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_getcwd, 0, 1), \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|EPERM),
        /* Send SIGSYS to process */
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)
    };
    struct sock_fprog prog;

    prog.len = sizeof(filter) / sizeof(filter[0]);
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

static void sigsys_sigaction(int s, siginfo_t *info, void *context __attribute__((unused)))
{
    assert(s == SIGSYS);
    assert(info != NULL && info->si_signo == SIGSYS);
    if (info->si_code != 1) {
        fprintf(stderr, "sigaction warning: unexpected info->si_signo, %d != 1.\n", info->si_signo);
    }
    if (info->si_arch != SECCOMP_AUDIT_ARCH) {
        fprintf(stderr, "sigaction error: unexpected info->si_arch, 0x%x != 0x%x.\n", info->si_arch, SECCOMP_AUDIT_ARCH);
        exit(1);
    }
    printf("Blocked syscall %d%s @%p\n", info->si_syscall,
           (info->si_syscall == __NR_uname) ? " (__NR_uname)" : "",
           info->si_call_addr);
    fflush(stdout);
    exit((info->si_syscall == __NR_uname) ? 0 : 1);
}

int main()
{
    char cwd[4096], *buf;
    struct utsname name;
    struct sigaction act;
    sigset_t mask;

    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = sigsys_sigaction;
    if (sigaction(SIGSYS, &act, 0) == -1) {
        perror("sigaction");
        return 1;
    }
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
        perror("sigprocmask");
        return 1;
    }

    if (!install_syscall_filter()) {
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

    /* Use yet another syscall to trigger SIGSYS */
    uname(&name);
    printf("Oh, I'm still alive! seccomp filters failed.\n");
    return 1;
}
