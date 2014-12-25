Arch Linux secure Kernel
========================

This directory contains what is needed to compile for Arch Linux a GNU/Linux
kernel which provides both grsecurity patches and SELinux config.

Related links:

* https://github.com/nning/linux-grsec ``linux-grsec`` package
* https://grsecurity.net grsecurity project website
* https://github.com/Siosm/siosm-selinux SELinux packages for Arch Linux


Kernel configuration
--------------------

Sysfs protection
~~~~~~~~~~~~~~~~
Several desktop application use ``/sys`` to get information about the system
like enumerating network interfaces, setting up audio cards, etc. Because of
this grsec's *Sysfs/debugfs restriction* needs to be disabled. This option is
named ``CONFIG_GRKERNSEC_SYSFS_RESTRICT`` and is located in menuconfig in::

   -> Security options
     -> Grsecurity
       -> Grsecurity (GRKERNSEC [=y])
         -> Customize Configuration
           -> Filesystem Protections
             [ ] Sysfs/debugfs restriction

Kernel ``.config``::

    # CONFIG_GRKERNSEC_SYSFS_RESTRICT is not set

Mmap minimal address
~~~~~~~~~~~~~~~~~~~~
By default ``CONFIG_DEFAULT_MMAP_MIN_ADDR=4096``. This is a protection against
NULL pointer dereference exploits which need to map memory at address 0. During
runtime the minimal address where a ``mmap`` is allowed can also be configured
with ``sysctl``::

    sysctl vm.mmap_min_addr
    cat /proc/sys/vm/mmap_min_addr

4096 may be considered too low and increasing it may improve security. Security
modules defines ``LSM_MMAP_MIN_ADDR`` in
http://lxr.free-electrons.com/source/security/Kconfig to 32768 on ARM and 65536
on other architectures. Hence this is changed in the configuration::

    CONFIG_DEFAULT_MMAP_MIN_ADDR=65536

SELinux support
~~~~~~~~~~~~~~~
Since 3.15 Arch Linux kernel doesn't provide any Linux Security Module nor the
audit subsystem.
(https://bugs.archlinux.org/task/37578 may improve the situation).
Therefore following configuration options need to be added to enable SELinux::

    CONFIG_AUDIT=y
    CONFIG_SECURITY=y
    CONFIG_SECURITY_NETWORK=y
    CONFIG_SECURITY_SELINUX=y
    CONFIG_SECURITY_SELINUX_BOOTPARAM=y
    CONFIG_SECURITY_SELINUX_DISABLE=y
    CONFIG_SECURITY_SELINUX_DEVELOP=y
    CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE=1
    CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=1
    CONFIG_SECURITY_SELINUX_ENABLE_SECMARK_DEFAULT=y
    CONFIG_SECURITY_SELINUX_AVC_STATS=y
    CONFIG_SECURITY_SELINUX_POLICYDB_VERSION_MAX=n
    CONFIG_LSM_MMAP_MIN_ADDR=65536
    CONFIG_DEFAULT_SECURITY_SELINUX=y

As these options enable new config fields, ``arch-linux-grsec-selinux`` adds a
bit more config values to the kernel configuration.


Grsecurity runtime configuration
--------------------------------

By default grsecurity prevents an user to see in ``/proc`` the processus she
doesn't own. This restriction can be turned off by adding users to
``proc-trusted`` group.

Some daemons like ``dbus`` and ``polkitd`` also needfull access to ``/proc`` to
be able to find process owners. This is done by issuing the following commands::

    gpasswd proc-trusted -a dbus
    gpasswd proc-trusted -a polkitd

NTPd needs to have read access to ``/proc/net/if_inet6`` to use IPv6
(http://support.ntp.org/bin/view/Support/KnownOsIssues#Section_9.2.4.2.5.1.)::

    gpasswd proc-trusted -a ntp

For an user to be able to run its own programs, she must belong to group
``tpe-trusted``. Also to do administrative actions without being ``root``,
being member of group ``adm`` is a good idea.


PAX runtime configuration
-------------------------

PAX mechanism prevents several actions from being done, like mapping memory
with both write and execute permissions. Some applications don't support these
restrictions. ``paxctl`` modify the header of a binary file so that the loader
knows what restriction to disable when launching the application. For example
this command removes the secure memory protections from ``truecrypt``::

    paxctl -cPSmXER /usr/bin/truecrypt

In Arch Linux, ``linux-pax-flags`` package provides a list of known applications
to configure. The associated command uses files from ``/etc/pax-flags/`` and
``/usr/share/linux-pax-flags/``.
