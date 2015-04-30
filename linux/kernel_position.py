#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Find the position of the kernel in memory

The following locations are used.

To read live kernel position:
* /proc/iomem, which contains "Kernel code", "Kernel data" and "Kernel bss".
* /proc/kallsyms, which contains the current position of symbols
  but may be unavailable for security reasons.

To read static kernel symbols:
* nm /lib/modules/$(uname -r)/build/vmlinux, when vmlinux file is available.
* /boot/System.map-$(uname -r), which contains the result of the previous
  command at build time.

It is also possible to extract vmlinux from an installed vmlinux file with
https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/scripts/extract-vmlinux
and then use "readelf -S" to read the section header of the extracted kernel to
get the static location of .text, .data and .bss segments.
"""
import collections
import itertools
import logging
import os.path
import platform
import re
import subprocess
import sys


logger = logging.getLogger(__name__)


# Internal name of kernel sections with symbols defining the start and end
KERNEL_SECTIONS = collections.OrderedDict((
    ('code', ('_text', '_etext')),
    ('data', ('_sdata', '_edata')),
    ('bss', ('__bss_start', '__bss_stop')),
))
KERNEL_SYMNAMES = list(itertools.chain(*KERNEL_SECTIONS.values()))


def symbols2positions(symbols):
    """Convert a symbols dict to section postions"""
    def dec_or_none(value):
        return value - 1 if value is not None else None
    return dict((
        (name, (symbols[syms[0]], dec_or_none(symbols[syms[1]])))
        for name, syms in KERNEL_SECTIONS.items()))


def show_positions_diff(pos1, pos2):
    """Show the differences between positions collected by 2 ways"""
    for symname in KERNEL_SECTIONS.keys():
        print("  {}:".format(symname))
        for endidx, endname in enumerate(('start', 'end  ')):
            p1 = pos1[symname][endidx]
            p2 = pos2[symname][endidx]
            if p1 is None and p2 is None:
                print("    {}: ?".format(endname))
            elif p1 is None:
                print("    {}: ? - {:x}".format(endname, p2))
            elif p2 is None:
                print("    {}: {:x} - ?".format(endname, p1))
            else:
                print("    {}: {:x} - {:x} ({}{:#x})".format(
                    endname, p1, p2, '+' if p2 > p1 else '', p2 - p1))


def get_pa2va_offset(machine=None):
    """Get the physical address to kernel virtual address offset for the
    specified architecture
    """
    if machine is None:
        machine = platform.machine()

    if re.match(r'armv[1-9]+l$', machine):
        # https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm/memory.txt
        return 0xc0000000  # PAGE_OFFSET
    elif re.match(r'i[3-6]86$', machine):
        return 0xc0000000  # CONFIG_PAGE_OFFSET default value
    elif machine == 'x86_64':
        # https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/x86/x86_64/mm.txt
        return 0xffffffff80000000  # __START_KERNEL_map

    logger.warning("Unknown pa2va offset for %s", machine)
    return 0


def get_kernel_pos_from_iomem(machine=None):
    """Get the position of some kernel segments using /proc/iomem"""
    logger.debug("reading live symbols from /proc/iomem")
    offset = get_pa2va_offset(machine)
    kernel_pos = dict(((name, None) for name in KERNEL_SECTIONS.keys()))
    with open('/proc/iomem', 'r') as fiomem:
        for line in fiomem:
            line = line.strip()
            matches = re.match(r'([0-9a-f]+)-([0-9a-f]+) : Kernel (.*)$', line)
            if matches is None:
                continue
            start, end, name = matches.groups()
            if name not in kernel_pos:
                logger.warning("unknown kernel part %s in /proc/iomem", name)
                continue
            kernel_pos[name] = (int(start, 16) + offset, int(end, 16) + offset)

    # Some architectures (like ARM) merge data and bss segments
    if kernel_pos['bss'] is None and kernel_pos['data'] is not None:
        kernel_pos['bss'] = (None, kernel_pos['data'][1])
        kernel_pos['data'] = (kernel_pos['data'][0], None)

    if None in kernel_pos.values():
        notfound = [name for name, addr in kernel_pos.items() if addr is None]
        logger.warning("unable to find kernel %s in /proc/iomem",
                       ', '.join(notfound))
        for name in notfound:
            kernel_pos[name] = (None, None)
    return kernel_pos


def get_pos_symbols_from_systemmap(path=None):
    """Get the symbols from a System.map file"""
    if path is None:
        path = '/boot/System.map-{}'.format(platform.release())
        if not os.path.exists(path):
            return
    logger.debug("reading symbols from %s", path)
    symbols = dict(((name, None) for name in KERNEL_SYMNAMES))
    with open(path, 'r') as fsysmap:
        for line in fsysmap:
            matches = re.match(r'([0-9a-f]+) . ([0-9a-zA-Z_]+)', line)
            if matches is None:
                continue
            addr, name = matches.groups()
            if name in symbols:
                if symbols[name] is not None:
                    logger.warning("symbol %s is defined twice, %x and %s",
                                   name, symbols[name], addr)
                symbols[name] = int(addr, 16)
    return symbols2positions(symbols)


def get_kernel_pos_from_kallsyms():
    """Get the position of some kernel segments using /proc/kallsyms"""
    if not os.path.exists('/proc/kallsyms'):
        return
    positions = get_pos_symbols_from_systemmap('/proc/kallsyms')
    if positions is None:
        return
    # With sysctl kernel.kptr_restrict, addresses may be null
    if all(not addrs[0] for addrs in positions.values()):
        # By the way, on ARM kallsyms does not have some symbols
        logger.warning("/proc/kallsyms access is restricted")
        return
    return positions


def get_pos_symbols_from_vmlinux(path=None):
    """Get the kernel position symbols from a vmlinux file"""
    if path is None:
        # Use a path from the current kernel
        path = '/lib/modules/{}/build/vmlinux'.format(platform.release())
        if not os.path.exists(path):
            return

    logger.debug("reading symbols from %s", path)

    symbols = dict(((name, None) for name in KERNEL_SYMNAMES))

    # Use nm on the vmlinux path
    proc = subprocess.Popen(['nm', path], stdout=subprocess.PIPE)
    for line in proc.stdout:
        sline = line.decode('ascii', errors='ignore').strip().split()
        if len(sline) != 3:
            continue
        addr = int(sline[0], 16)
        name = sline[2]
        if name in symbols:
            if symbols[name] is not None:
                logger.warning("symbol %s is defined twice, %x and %x",
                               name, symbols[name], addr)
            symbols[name] = addr

    retval = proc.wait()
    if retval:
        logger.error("nm exited with status %d", retval)
        return
    return symbols2positions(symbols)


def main():
    """Show the kernel offset in current memory"""
    emptypos = dict(((name, (None, None)) for name in KERNEL_SECTIONS.keys()))

    # Get the current live kernel position
    iomem = get_kernel_pos_from_iomem()
    kallsyms = get_kernel_pos_from_kallsyms()
    if iomem is not None and kallsyms is not None and iomem != kallsyms:
        print("/proc/iomem and /proc/kallsyms disagree!")
        show_positions_diff(iomem, kallsyms)
        print("")
    livepos = iomem or kallsyms
    if livepos is None:
        logger.error("Unable to read the live kernel position")
        livepos = emptypos

    # Get static section positions from the symbols
    vmlinux = get_pos_symbols_from_vmlinux()
    sysmap = get_pos_symbols_from_systemmap()
    if vmlinux is not None and sysmap is not None and vmlinux != sysmap:
        print("vmlinux and System.map symbols differ!")
        show_positions_diff(vmlinux, sysmap)
        print("")
    staticpos = vmlinux or sysmap
    if staticpos is None:
        logger.error("Unable to read the static kernel symbols")
        staticpos = emptypos

    print("Static to current live kernel positions:")
    show_positions_diff(staticpos, livepos)
    return 0

if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG)
    sys.exit(main())
