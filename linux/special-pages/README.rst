Linux kernel special pages
==========================

Linux kernel maps some special pages to user process.  A process can view these
pages in ``/proc/self/maps`` as memory ranges with a description in brackets,
like ``[stack]`` and ``[heap]``.  Apart from containing data, some memory pages
can be used to:

* run arbitrary system calls (``[vsyscall]``, on i386),
* handle the signal trampoline to call sigreturn when a signal handler returns
  (cf. ``man 2 sigreturn``, ``[sigpage]`` on ARM),
* retrieve the current cpu (``getcpu``) and time information (``gettimeofday``)
  without switching to kernel mode, using architecture-dependent tricks.

Some architectures (like x86) have a Virtual Dynamic Shared Object, named
``[vdso]``, which can contain some code.


ARM pages
---------

* ``[sigpage]``: page containing trampolines for sigreturn.

* ``[vectors]``, ``0xffff0000-0xffff1000``: ARM vectors and user helpers.
  The ARM vecors code mainly contains branching instructions to the next page
  (at ``0xffff1000``), unreadable from userspace.
  If ``CONFIG_KUSER_HELPERS`` is set, the end of the page contains
  Kernel-provided User Helpers:

  - ``0xffff0ffc``: ``kuser_helper_version``, number of present helpers
  - ``0xffff0fe0``: ``kuser_get_tls``, helper 1
  - ``0xffff0fc0``: ``kuser_cmpxchg``, helper 2
  - ``0xffff0fa0``: ``kuser_memory_barrier``, helper 3
  - ``0xffff0f60``: ``kuser_cmpxchg64``, helper 5 (also uses slot 4)


x86-32 pages
------------

* ``[vvar]``: vDSO variables.

* ``[vdso]``: vDSO, ELF shared object with these symbols:

  - ``__kernel_rt_sigreturn``
  - ``__kernel_sigreturn``
  - ``__kernel_vsyscall``
  - ``__vdso_clock_gettime``
  - ``__vdso_gettimeofday``
  - ``__vdso_time``


x86-64 pages
------------

* ``[vvar]``: vDSO variables.

* ``[vdso]``: vDSO, ELF shared object with these symbols:

  - ``__vdso_clock_gettime`` and weak symbol ``clock_gettime``
  - ``__vdso_getcpu`` and weak symbol ``getcpu``
  - ``__vdso_gettimeofday`` and weak symbol ``gettimeofday``
  - ``__vdso_time`` and weak symbol ``time``

* ``[vsyscall]`` at ``0xffffffffff600000``: syscall traps (legacy).
  If ``CONFIG_X86_VSYSCALL_EMULATION`` is set, this page contains syscalls at
  fixed locations:

  - ``0xffffffffff600000``: ``gettimeofday`` (syscall 96)
  - ``0xffffffffff600400``: ``time`` (syscall 201)
  - ``0xffffffffff600800``: ``getcpu`` (syscall 309)


Documentation
-------------
* https://www.kernel.org/doc/Documentation/ABI/stable/vdso
  vDSO ABI
* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/vdso
  x86 vDSO
* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/arm/kernel/sigreturn_codes.S
  Content of ARM ``[sigpage]`` page.
* https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt
  ARM Kernel-provided User Helpers, located in ``[vectors]``.
* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/arm/kernel/entry-armv.S
  Implementation of ARM vector pages
* http://man7.org/linux/man-pages/man2/sigreturn.2.html ``man 2 sigreturn``
