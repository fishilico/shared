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

At the entry points, the stack contains the arguments and environment of the
program. If ``sp`` is the stack pointer (``esp`` on x86, ``rsp`` on x86_64 and
``sp`` on ARM), and ``n`` the size in bytes of a pointer (4 on a 32-bits adress
architecture, 8 on a 64-bits one), then ``argc``, ``argv`` and ``envp`` are
organised as follows.

+-------------------------------+--------------+
|    Address                    |    Content   |
+===============================+==============+
|  ``sp``                       |  ``argc``    |
+-------------------------------+--------------+
|  ``sp + n``                   |  ``argv[0]`` |
+-------------------------------+--------------+
|  ...                          |  ...         |
+-------------------------------+--------------+
|  ``sp + n * i``               |  ``argv[i]`` |
+-------------------------------+--------------+
|  ...                          |  ...         |
+-------------------------------+--------------+
|  ``sp + n * argc``            |  ``NULL``    |
+-------------------------------+--------------+
|  ``sp + n * (argc + 1)``      |  ``envp[0]`` |
+-------------------------------+--------------+
|  ...                          |  ...         |
+-------------------------------+--------------+
|  ``sp + n * (argc + 1 + i)``  |  ``envp[i]`` |
+-------------------------------+--------------+
|  ...                          |  ...         |
+-------------------------------+--------------+
|  ``sp + n * (argc + ...)``    |  ``NULL``    |
+-------------------------------+--------------+


Documentation links
-------------------

Here are some links to documentation websites.

GCC inline ASM:

* http://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
* http://gcc.gnu.org/onlinedocs/gcc/Constraints.html
* http://www.ibm.com/developerworks/library/l-ia/
* http://locklessinc.com/articles/gcc_asm/

glibc source code: https://sourceware.org/git/?p=glibc.git

With ``$ARCH`` being x86, x86_64 or arm, ``syscall()`` is implemented in
``sysdeps/unix/sysv/linux/$ARCH/syscall.S`` and ``_start()`` in
``sysdeps/$ARCH/start.S``.

Related works:

* http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
  A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux
