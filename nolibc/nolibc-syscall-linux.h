/**
 * GNU/Linux system call wrappers which don't use the C library
 */

#ifndef NOLIBC_SYSCALL_LINUX_H
#define NOLIBC_SYSCALL_LINUX_H

/* Import the lists of error numbers and system calls */
#include <errno.h>
#include <sys/syscall.h>

/**
 * Program entry point
 */
void _start(void) __attribute__((noreturn));

/**
 * Define System Call with 3 arguments for each supported architectures
 *
 * Here are some documentation links:
 * * http://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
 * * http://gcc.gnu.org/onlinedocs/gcc/Constraints.html
 * * http://www.ibm.com/developerworks/library/l-ia/
 * * https://sourceware.org/git/?p=glibc.git glibc source code, with:
 *     sysdeps/unix/sysv/linux/i386/syscall.S
 *     sysdeps/unix/sysv/linux/x86_64/syscall.S
 */
static long _syscall3(
    int number, unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
    long result;
#if defined __x86_64__
    /* rax = syscall number and result
     * rdi = arg1
     * rsi = arg2
     * rdx = arg3
     * r10 = arg4
     * r8  = arg5
     * r9  = arg6
     */
    __asm__ volatile ("syscall"
        : "=a" (result)
        : "0" (number), "D" (arg1), "S" (arg2), "d" (arg3)
        : "memory", "cc", "r11", "cx");
#elif defined __i386__
    /* eax = syscall number and result
     * ebx = arg1
     * ecx = arg2
     * edx = arg3
     * esi = arg4
     * edi = arg5
     * ebp = arg6
     */
#if defined __GNUC__ && defined __pic__
    /* GCC with PIC flag (Program Independent Code) complains with
     * "error: inconsistent operand constraints in an 'asm'"
     * because ebx has a special meaning in PIC
     */
    __asm__ volatile ("push %%ebx ; movl %2, %%ebx ; int $0x80 ; pop %%ebx"
        : "=a" (result)
        : "0" (number), "g" (arg1), "c" (arg2), "d" (arg3)
        : "memory", "cc");
#else
    __asm__ volatile ("int $0x80"
        : "=a" (result)
        : "0" (number), "b" (arg1), "c" (arg2), "d" (arg3)
        : "memory", "cc");
#endif
#else
#error Unsuported architecture
#endif
    return result;
}
#define syscall3(num, arg1, arg2, arg3) _syscall3((num), \
    (unsigned long)(arg1), (unsigned long)(arg2), (unsigned long)(arg3))
#define syscall2(num, arg1, arg2) syscall3((num), (arg1), (arg2), 0)
#define syscall1(num, arg1) syscall2((num), (arg1), 0)
#define syscall0(num) syscall1((num), 0)

/**
 * Exit current process
 */
static void __attribute__((noreturn)) exit(int status)
{
    while(1) {
#ifdef __NR_exit_group
        syscall1(__NR_exit_group, status);
#endif
        syscall1(__NR_exit, status);
    }
}

/**
 * Write all count bytes from buf to file descriptor fd
 * Return value: 0 if an error occured, 1 if successful
 */
static int write_all(int fd, const char *buf, unsigned long count)
{
    while (count > 0) {
        long int ret = syscall3(__NR_write, fd, buf, count);
        if (ret == -EINTR) {
            continue;
        }
        if (ret <= 0) {
            return 0;
        }
        buf += ret;
        count -= ret;
    }
    return 1;
}

/**
 * Execute program
 */
static int execve(const char *filename, char *const argv[],
                   char *const envp[])
{
    return (int) syscall3(__NR_execve, filename, argv, envp);
}

#endif /* NOLIBC_SYSCALL_H */
