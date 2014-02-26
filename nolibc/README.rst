Program in C without any C library
==================================

A C library (GNU libc, eglibc...) is useful to write portable code in C. It
makes it easy to use memory allocation, wraps system calls into nice APIs and
provides an easy way to interact with the user (via command line arguments,
printf...).

This directory contains very simple basic which shows how one can write C code
without using any code from the C library. There are some assembly instructions
for the syscall interface with the operating system but everything else is C.
The entry point of such program is::

    void _start(void) __attribute__((noreturn));

and the program ends when the ``exit`` system call is issued, with an exit value
as parameter.

Documentation links
-------------------

Here are some links to documentation websites.

GCC inline ASM:

* http://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
* http://gcc.gnu.org/onlinedocs/gcc/Constraints.html
* http://www.ibm.com/developerworks/library/l-ia/
* http://locklessinc.com/articles/gcc_asm/

glibc source code: https://sourceware.org/git/?p=glibc.git

``syscall()`` is implemented in:

* sysdeps/unix/sysv/linux/i386/syscall.S
* sysdeps/unix/sysv/linux/x86_64/syscall.S
