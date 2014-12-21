#!/usr/bin/env python
"""Test the mmap_file module"""
import mmap
import os
import sys

# Retrieve the name of the file to be mmap'ed
with open('/sys/module/mmap_file/parameters/debugname', 'r') as f:
    file_path = '/sys/kernel/debug/' + f.readline().strip()

print("Opening {}".format(file_path))
with open(file_path, 'r+b', buffering=0) as f:
    size = os.fstat(f.fileno()).st_size
    print("Size: {} bytes".format(size))
    mm = mmap.mmap(f.fileno(), 0)
    print("First line: {}".format(mm.readline().decode('utf-8').strip()))

    # Second line contains the page size
    page_size_line = mm.readline().strip()
    if not page_size_line.startswith(b'page size is'):
        print("Unexpected second line: {}".format(page_size_line))
        sys.exit(1)
    page_size = int(page_size_line.decode('ascii').split('is', 1)[1])

    # Read 3 pages
    for i in range(3):
        offset = (i + 1) * page_size
        mm.seek(offset)
        print("@{:5d}: {}".format(offset, mm.readline().decode('utf-8').strip()))
