Mmap-WX testing project
=======================

This projects aims to test how to execute code which has previously been written
to a memory page

Such project can be used for programs which use Just-In-Time (JIT) compiling or
other similar feature. For example, libffi (which is used by Python) implements
similar code for ``void* ffi_closure_alloc(size_t size, void **code)`` (cf.
in https://github.com/atgreen/libffi/blob/master/src/closures.c).


Direct WX mmap restriction
--------------------------
By default on Linux, ``mmap`` with both ``PROT_WRITE`` and ``PROT_EXEC`` (WX) is
allowed. Using a grsecurity kernel with ``PAX_PAGEEXEC`` and ``PAX_MPROTECT``
will deny such ``mmap`` call. The only way to allow it then is to disable
memory restrictions on the executable::

    paxctl -cm mmap-wx

Then, the program will give this kind of output::

    [ ] RWX mmap succeeded at 0x7672ca102000, let's try to use it!
    [!] Code successfully executed. Your kernel is NOT secure!

Output sample with a grsecurity kernel
--------------------------------------
Program output::

    [+] Direct RWX mmap failed as expected with a secure kernel

    [ ] Testing /tmp
    ... created file /tmp/mmap-wx-tmpXoRKx7
    [!] mmap-RX: Permission denied

    [ ] Testing current directory
    ... created file ./mmap-wx-tmp8M26CK
    ... RW+RX mmap succeeded at 0x79434be1c000 and 0x79434be1b000
    [+] Code successfully executed

Kernel log::

    grsec: denied RWX mmap of <anonymous mapping> by /.../mmap-wx/mmap-wx[mmap-wx:7538] uid/euid:1000/1000 gid/egid:100/100, parent ... uid/euid:1000/1000 gid/egid:100/100
    grsec: denied untrusted exec (due to file in world-writable directory) of /tmp/mmap-wx-tmpXoRKx7 by /.../mmap-wx/mmap-wx[mmap-wx:7538] uid/euid:1000/1000 gid/egid:100/100, parent ... uid/euid:1000/1000 gid/egid:100/100
