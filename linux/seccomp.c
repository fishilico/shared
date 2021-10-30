/**
 * Use seccomp filters to restrict syscalls
 *
 * Linux examples: http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/samples/seccomp
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for sigaction, sigemptyset, sigprocmask, syscall */
#endif

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h> /* for offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* for memset */
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <ucontext.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/**
 * Define AUDIT_ARCH and helpers to mcontext_t struct
 * mcontext_t is defined in /usr/include/sys/ucontext.h
 */
#if defined(__i386__)
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#    define mctx_reg_result(mctx) (mctx).gregs[REG_EAX]
#    define mctx_reg_syscall(mctx) (mctx).gregs[REG_EAX]
#    define mctx_reg_arg0(mctx) (mctx).gregs[REG_EBX]
#    define mctx_reg_arg1(mctx) (mctx).gregs[REG_ECX]
#    define mctx_reg_arg2(mctx) (mctx).gregs[REG_EDX]
#    define mctx_reg_arg3(mctx) (mctx).gregs[REG_ESI]
#    define mctx_reg_arg4(mctx) (mctx).gregs[REG_EDI]
#    define mctx_reg_arg5(mctx) (mctx).gregs[REG_EBP]
#elif defined(__x86_64__)
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#    define mctx_reg_result(mctx) (mctx).gregs[REG_RAX]
#    define mctx_reg_syscall(mctx) (mctx).gregs[REG_RAX]
#    define mctx_reg_arg0(mctx) (mctx).gregs[REG_RDI]
#    define mctx_reg_arg1(mctx) (mctx).gregs[REG_RSI]
#    define mctx_reg_arg2(mctx) (mctx).gregs[REG_RDX]
#    define mctx_reg_arg3(mctx) (mctx).gregs[REG_R10]
#    define mctx_reg_arg4(mctx) (mctx).gregs[REG_R8]
#    define mctx_reg_arg5(mctx) (mctx).gregs[REG_R9]
#elif defined(__aarch64__)
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#    define mctx_reg_result(mctx) (mctx).regs[0]
#    define mctx_reg_syscall(mctx) (mctx).regs[8]
#    define mctx_reg_arg0(mctx) (mctx).regs[0]
#    define mctx_reg_arg1(mctx) (mctx).regs[1]
#    define mctx_reg_arg2(mctx) (mctx).regs[2]
#    define mctx_reg_arg3(mctx) (mctx).regs[3]
#    define mctx_reg_arg4(mctx) (mctx).regs[4]
#    define mctx_reg_arg5(mctx) (mctx).regs[5]
#elif defined(__arm__)
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#    define mctx_reg_result(mctx) (mctx).arm_r0
#    define mctx_reg_syscall(mctx) (mctx).arm_r7
#    define mctx_reg_arg0(mctx) (mctx).arm_r0
#    define mctx_reg_arg1(mctx) (mctx).arm_r1
#    define mctx_reg_arg2(mctx) (mctx).arm_r2
#    define mctx_reg_arg3(mctx) (mctx).arm_r3
#    define mctx_reg_arg4(mctx) (mctx).arm_r4
#    define mctx_reg_arg5(mctx) (mctx).arm_r5
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
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_brk, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#ifdef __NR_mmap
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#endif
#ifdef __NR_mmap2
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap2, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigreturn, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        /* Allow writing only to stderr and stdout */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 1, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_writev, 0, 5),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + SYSCALL_ARG_OFFSET),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDOUT_FILENO, 1, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDERR_FILENO, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

        /* Allow ioctl on stdout */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_ioctl, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + SYSCALL_ARG_OFFSET),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDOUT_FILENO, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

        /* Allow fstat on stdout */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + SYSCALL_ARG_OFFSET),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDOUT_FILENO, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
#ifdef __NR_fstat64
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat64, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + SYSCALL_ARG_OFFSET),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDOUT_FILENO, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
#endif
#ifdef __NR_newfstatat
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_newfstatat, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + SYSCALL_ARG_OFFSET),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDOUT_FILENO, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
#endif
#ifdef __NR_statx
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_statx, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + SYSCALL_ARG_OFFSET),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, STDOUT_FILENO, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
#endif

        /* Allow getrandom, used by glibc on Fedora 35 to use the heap */
#ifdef __NR_getrandom
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getrandom, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
#endif

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
        if (errno == EINVAL) {
            fprintf(stderr, "Exit because the kernel does not support prctl(PR_SET_NO_NEW_PRIVS).\n");
            /* Exit with a success value because nothing really failed, there is only nothing available. */
            exit(0);
        }
        perror("prctl(NO_NEW_PRIVS)");
        return false;
    }
#if defined(__NR_seccomp) && defined(SECCOMP_SET_MODE_FILTER)
    /* Use seccomp syscall if available (Linux >= 3.17) */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0) {
        return true;
    }
#endif
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        if (errno == EINVAL) {
            fprintf(stderr, "Exit because the kernel does not support seccomp filters.\n");
            exit(0);
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
    greg_t syscall_nr, arg0, arg1;
    void *call_addr;

    assert(s == SIGSYS);
    assert(info != NULL && info->si_signo == SIGSYS);
    if (info->si_code != 1) {
        fprintf(stderr, "sigaction warning: unexpected info->si_signo, %d != 1.\n", info->si_signo);
    }
#ifdef si_arch
    if (info->si_arch != SECCOMP_AUDIT_ARCH) {
        fprintf(stderr,
                "sigaction error: unexpected info->si_arch, 0x%x != 0x%x.\n",
                info->si_arch, SECCOMP_AUDIT_ARCH);
        exit(1);
    }
#endif

    if (!ctx) {
        fprintf(stderr, "sigaction error: no context has been given.\n");
        exit(1);
    }
    syscall_nr = mctx_reg_syscall(ctx->uc_mcontext);

    /* If the libc knows info->si_syscall, use it for a sanity check */
#ifdef si_syscall
    assert(syscall_nr == (greg_t)info->si_syscall);
#endif

    /* Emulate getpriority */
    if (syscall_nr == __NR_getpriority) {
        arg0 = mctx_reg_arg0(ctx->uc_mcontext);
        arg1 = mctx_reg_arg1(ctx->uc_mcontext);
        if (arg0 == PRIO_USER && arg1 == 0) {
            mctx_reg_result(ctx->uc_mcontext) = 42;
            return;
        }
    }

#ifdef si_call_addr
    call_addr = info->si_call_addr;
#else
    call_addr = NULL;
#endif
    /* Block the syscall */
    printf("Blocked syscall %d%s @%p\n", (int)syscall_nr,
           (syscall_nr == __NR_uname) ? " (__NR_uname)" : "",
           call_addr);
    fflush(stdout);
    exit((syscall_nr == __NR_uname) ? 0 : 1);
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
        /* Do not use perror as this may call dup with glibc:
         * https://sourceware.org/git/?p=glibc.git;a=blob;f=stdio-common/perror.c;hb=b8079dd0d360648e4e8de48656c5c38972621072
         */
        fprintf(stderr, "getpriority(user root): %s\n", strerror(errno));
        return 1;
    }

    /* Use yet another syscall to trigger SIGSYS */
    uname(&name);
    printf("Oh, I'm still alive! seccomp filters failed.\n");
    return 1;
}
