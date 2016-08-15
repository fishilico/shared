Shellcodes
==========

This directory contains code for several machine configuration to be able to
spawn an application from a limited execution environment (mostly without the
shortcuts given by a file format such as ELF or PE).  Such code is usually
named *shellcode* and can be used in an exploit scenario when the execution of
a program is directed towards untrusted user input.

The operation of a shellcode depends on the operating system:

* On Linux, it launches a shell by running this system call (``/bin//sh`` is
  used instead of ``/bin/sh`` to avoid NUL characters in the shellcode):

.. code-block:: c

    execve("/bin//sh", ["/bin//sh"], NULL)

* On Windows, it launches ``cmd.exe`` with:

.. code-block:: c

    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(STARTUPINFOA);
    CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi));
    WaitForSingleObject(pi.hProcess, INFINITE);
    ExitProcess(0);


Related websites
----------------

* http://shell-storm.org/shellcode/
  Shellcodes database for study cases
* http://www.nologin.org/Downloads/Papers/win32-shellcode.pdf
  Understanding Windows Shellcode
* http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html
  Writing Optimized Windows Shellcode in C
* https://github.com/longld/peda/blob/master/lib/shellcode.py
  gdb-peda shellcodes

* https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/exec.rb
  Metasploit payload to run WinExec() in 32-bit Windows.
  Used by ``msfvenom -p windows/exec cmd=calc``
