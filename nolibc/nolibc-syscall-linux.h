/**
 * GNU/Linux system call wrappers which don't use the C library
 */

#ifndef NOLIBC_SYSCALL_LINUX_H
#define NOLIBC_SYSCALL_LINUX_H

/* Import the lists of error numbers and system calls */
#include <errno.h>
#include <asm/unistd.h>
#include <sys/types.h>

/**
 * Program entry point
 */
void _start(void) __attribute__((noreturn));

/**
 * Define System Call with 3 arguments for each supported architectures
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
#if defined __GNUC__ && defined __PIC__
    /* GCC with PIC flag (Program Independent Code) complains with
     * "error: inconsistent operand constraints in an 'asm'"
     * because ebx has a special meaning in PIC
     */
    __asm__ volatile ("xchgl %%ebx, %2 ; int $0x80 ; xchgl %%ebx, %2"
        : "=a" (result)
        : "0" (number), "r" (arg1), "c" (arg2), "d" (arg3)
        : "memory", "cc");
#else
    __asm__ volatile ("int $0x80"
        : "=a" (result)
        : "0" (number), "b" (arg1), "c" (arg2), "d" (arg3)
        : "memory", "cc");
#endif
#else
#error Unsupported architecture
#endif
    return result;
}
#define syscall3(num, arg1, arg2, arg3) _syscall3((num), \
    (unsigned long)(arg1), (unsigned long)(arg2), (unsigned long)(arg3))
#define syscall2(num, arg1, arg2) syscall3((num), (arg1), (arg2), 0)
#define syscall1(num, arg1) syscall2((num), (arg1), 0)
#define syscall0(num) syscall1((num), 0)

/**
 * Simple system calls
 */
static int open3(const char *pathname, int flags, mode_t mode)
{
    return (int)syscall3(__NR_open, pathname, flags, mode);
}
static int open2(const char *pathname, int flags)
{
    return open3(pathname, flags, 0);
}
static int close(int fd)
{
    return (int)syscall1(__NR_close, fd);
}
static ssize_t read(int fd, const void *buf, size_t count)
{
    return (ssize_t)syscall3(__NR_read, fd, buf, count);
}
static ssize_t write(int fd, const void *buf, size_t count)
{
    return (ssize_t)syscall3(__NR_write, fd, buf, count);
}

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
 * Read a file in a buffer, looping if the call is interrupted
 */
static ssize_t read_buffer(int fd, const void *buf, size_t count)
{
    ssize_t ret;
    do {
        ret = read(fd, buf, count);
    } while (ret == -EINTR);
    return ret;
}

/**
 * Write all count bytes from buf to file descriptor fd
 * Return value: 0 if an error occured, 1 if successful
 */
static int write_all(int fd, const char *buf, size_t count)
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
        count -= ret;
    }
    return 1;
}

/**
 * Get the length of a string
 */
static size_t strlen(const char *str)
{
    /* This is really inefficient but works */
    const char *ptr = str;
    while (*ptr) {
        ptr++;
    }
    return (size_t)(ptr - str);
}

/**
 * Write a nul-terminated string to file descriptor fd
 * Return value: same as write_all
 */
static int write_string(int fd, const char *str)
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
static int write_ulong(int fd, unsigned long l)
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
static int execve(const char *filename, char *const argv[],
                   char *const envp[])
{
    return (int) syscall3(__NR_execve, filename, argv, envp);
}

#endif /* NOLIBC_SYSCALL_H */
