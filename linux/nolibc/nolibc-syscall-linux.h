/**
 * GNU/Linux system call wrappers which don't use the C library
 */

#ifndef NOLIBC_SYSCALL_LINUX_H
#define NOLIBC_SYSCALL_LINUX_H

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for AT_FDCWD */
#endif

/* Import the lists of error numbers and system calls */
/*#define _GNU_SOURCE*/
#include <errno.h>
#include <fcntl.h> /* for AT_FDCWD */
#include <stddef.h> /* for size_t */
#include <sys/syscall.h>
#include <sys/types.h> /* for ssize_t */

/**
 * Program entry point
 */
void _start(void) __attribute__((noreturn));

/* Force all functions to be inlined, to produce simple shellcodes */
#define ALWAYS_INLINE __inline__ __attribute__((always_inline))

/**
 * Define System Call with 4 arguments for each supported architectures
 */
static ALWAYS_INLINE long _syscall4(
    int number, unsigned long arg1, unsigned long arg2, unsigned long arg3,
    unsigned long arg4)
{
    long result;
#if defined(__x86_64__)
    /* rax = syscall number and result
     * rdi = arg1
     * rsi = arg2
     * rdx = arg3
     * r10 = arg4
     * r8  = arg5
     * r9  = arg6
     */
    register long r10 __asm__("r10") = (long)arg4;
    __asm__ volatile ("syscall"
        : "=a" (result)
        : "0" (number), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10)
        : "cc", "memory", "rcx", "r8", "r9", "r11");
#elif defined(__i386__)
    /* eax = syscall number and result
     * ebx = arg1
     * ecx = arg2
     * edx = arg3
     * esi = arg4
     * edi = arg5
     * ebp = arg6
     */
#    if defined(__GNUC__) && defined(__PIC__)
    /* GCC with PIC flag (Program Independent Code) complains with
     * "error: inconsistent operand constraints in an 'asm'"
     * because ebx has a special meaning in PIC
     */
    __asm__ volatile ("xchgl %%ebx, %2 ; int $0x80 ; xchgl %%ebx, %2"
        : "=a" (result)
        : "0" (number), "r" (arg1), "c" (arg2), "d" (arg3), "S" (arg4)
        : "memory", "cc");
#    else
    __asm__ volatile ("int $0x80"
        : "=a" (result)
        : "0" (number), "b" (arg1), "c" (arg2), "d" (arg3), "S" (arg4)
        : "memory", "cc");
#    endif
#elif defined(__aarch64__)
    /* x8 = syscall number
     * x0 = arg1 and result
     * x1 = arg2
     * x2 = arg3
     * x3 = arg4
     * x4 = arg5
     * x5 = arg6
     */
    register long x8 __asm__("x8") = (long)(unsigned int)number;
    register long x0 __asm__("x0") = (long)arg1;
    register long x1 __asm__("x1") = (long)arg2;
    register long x2 __asm__("x2") = (long)arg3;
    register long x3 __asm__("x3") = (long)arg4;
    __asm__ volatile ("svc #0"
        : "=r" (x0)
        : "0" (x0), "r" (x1), "r" (x2), "r" (x3), "r" (x8)
        : "memory", "cc", "x4", "x5", "x6");
    result = x0;
#elif defined(__arm__)
    /* r7 = syscall number
     * r0 = arg1 and result
     * r1 = arg2
     * r2 = arg3
     * r3 = arg4
     * r4 = arg5
     * r5 = arg6
     */
    register long r7 __asm__("r7") = (long)(unsigned int)number;
    register long r0 __asm__("r0") = (long)arg1;
    register long r1 __asm__("r1") = (long)arg2;
    register long r2 __asm__("r2") = (long)arg3;
    register long r3 __asm__("r3") = (long)arg4;
    __asm__ volatile ("swi $0"
        : "=r" (r0)
        : "0" (r0), "r" (r1), "r" (r2), "r" (r3), "r" (r7)
        : "memory", "cc", "r4", "r5", "r6");
    result = r0;
#else
#    error Unsupported architecture
#endif
    return result;
}
#define syscall4(num, arg1, arg2, arg3, arg4) _syscall4((num), \
    (unsigned long)(arg1), (unsigned long)(arg2), (unsigned long)(arg3), \
    (unsigned long)(arg4))
#define syscall3(num, arg1, arg2, arg3) syscall4((num), (arg1), (arg2), (arg3), 0)
#define syscall2(num, arg1, arg2) syscall3((num), (arg1), (arg2), 0)
#define syscall1(num, arg1) syscall2((num), (arg1), 0)
#define syscall0(num) syscall1((num), 0)

/**
 * Simple system calls
 */
static ALWAYS_INLINE int open3(const char *pathname, int flags, mode_t mode)
{
#ifdef __NR_openat
    return (int)syscall4(__NR_openat, AT_FDCWD, pathname, flags, mode);
#else
    return (int)syscall3(__NR_open, pathname, flags, mode);
#endif
}
static ALWAYS_INLINE int open2(const char *pathname, int flags)
{
    return open3(pathname, flags, 0);
}
static ALWAYS_INLINE int close(int fd)
{
    return (int)syscall1(__NR_close, fd);
}
static ALWAYS_INLINE ssize_t read(int fd, const void *buf, size_t count)
{
    return (ssize_t)syscall3(__NR_read, fd, buf, count);
}
static ALWAYS_INLINE ssize_t write(int fd, const void *buf, size_t count)
{
    return (ssize_t)syscall3(__NR_write, fd, buf, count);
}

/**
 * Exit current process
 */
static ALWAYS_INLINE void __attribute__((noreturn)) nolibc_exit(int status)
{
    while (1) {
#ifdef __NR_exit_group
        syscall1(__NR_exit_group, status);
#endif
        syscall1(__NR_exit, status);
    }
}
#define exit(status) nolibc_exit(status) /* Be fine with -Wshadow */

/**
 * Read a file in a buffer, looping if the call is interrupted
 */
static ALWAYS_INLINE ssize_t read_buffer(int fd, const void *buf, size_t count)
{
    ssize_t ret;
    do {
        ret = read(fd, buf, count);
    } while (ret == -EINTR);
    return ret;
}

/**
 * Write all count bytes from buf to file descriptor fd
 * Return value: 0 if an error occurred, 1 if successful
 */
static ALWAYS_INLINE int write_all(int fd, const char *buf, size_t count)
{
    while (count > 0) {
        ssize_t ret = write(fd, buf, count);
        if (ret == -EINTR) {
            continue;
        }
        if (ret <= 0) {
            return 0;
        }
        buf += ret;
        count -= (size_t)ret;
    }
    return 1;
}

/**
 * Get the length of a string
 */
static ALWAYS_INLINE size_t nolibc_strlen(const char *str)
{
    /* This is really inefficient but works */
    const char *ptr = str;
    while (*ptr) {
        ptr++;
    }
    return (size_t)(ptr - str);
}
#define strlen(str) nolibc_strlen(str) /* Be fine with -Wshadow */

/**
 * Write a nul-terminated string to file descriptor fd
 * Return value: same as write_all
 */
static ALWAYS_INLINE int write_string(int fd, const char *str)
{
    return write_all(fd, str, strlen(str));
}
/**
 * Efficient implementation for constant strings
 */
#define write_cstring(fd, str) write_all((fd), (str), sizeof((str)) - 1)

/**
 * Write an unsigned long to a file descriptor
 */
static ALWAYS_INLINE int write_ulong(int fd, unsigned long l)
{
    char buffer[sizeof(unsigned long) * 3 + 1], *ptr;

    if (!l) {
        return write_cstring(fd, "0");
    }

    ptr = &(buffer[sizeof(buffer) - 1]);
    while (l) {
        *(ptr--) = '0' + (char)(l % 10);
        l /= 10;
        if (ptr < buffer) {
            write_cstring(2, "BUG: number too long for buffer\n");
            exit(255);
        }
    }
    return write_all(fd, ptr + 1, sizeof(buffer) - (size_t)(ptr + 1 - buffer));
}

/**
 * Execute program
 */
static ALWAYS_INLINE int execve(const char *filename, char *const argv[], char *const envp[])
{
    return (int)syscall3(__NR_execve, filename, argv, envp);
}

/**
 * Create a new process
 */
static ALWAYS_INLINE int fork(void)
{
    return (int)syscall0(__NR_fork);
}

/**
 * Wait for a process
 */
static ALWAYS_INLINE int wait4(int pid, int *wstatus, int options, void *rusage)
{
    return (int)syscall4(__NR_wait4, pid, wstatus, options, rusage);
}

#endif /* NOLIBC_SYSCALL_H */
