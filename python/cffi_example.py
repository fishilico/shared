#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Example of cffi library to interact with a C dynamic library

@author: Nicolas Iooss
"""
import cffi
import os
import os.path
import weakref


# Save initial $CC value
initial_cc = os.environ.get('CC')

# Call functions from the standard lib C library
ffi = cffi.FFI()
ffi.cdef("""
    typedef unsigned int gid_t;
    typedef unsigned int uid_t;
    typedef int pid_t;

    gid_t getgid(void);
    uid_t getuid(void);
    pid_t getpid(void);
""")
libc = ffi.dlopen(None)
print("getuid() = {}".format(libc.getuid()))
print("getgid() = {}".format(libc.getgid()))
print("getpid() = {}".format(libc.getpid()))


# Use ffi.verify to compile code
ffi = cffi.FFI()
ffi.cdef('const size_t LONG_SIZE;')
try:
    libv = ffi.verify('const size_t LONG_SIZE = sizeof(long);')
except cffi.VerificationError as exc:
    # This may have when using a custom $CC
    if initial_cc:
        print(exc)
        print("... Warning: cffi.verify failed with CC={}, retrying without".format(repr(initial_cc)))
        del os.environ['CC']
        libv = ffi.verify('const size_t LONG_SIZE = sizeof(long);')
        os.environ['CC'] = initial_cc
    else:
        raise
print("sizeof(long) = {}".format(libv.LONG_SIZE))


# Add C definitions from header file, without any preprocessor macro
ffi = cffi.FFI()
current_dir = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(current_dir, 'cffi_example.h'), 'r') as fhead:
    cdefs = [line.replace('CFFI_EXAMPLE_API', '')
             for line in fhead if not line.lstrip().startswith('#')]
    ffi.cdef(''.join(cdefs))

filepath = os.path.join(current_dir, '_cffi_example')
if os.name == 'nt':
    filepath += '.dll'
elif os.name == 'posix':
    filepath += '.so'
else:
    raise RuntimeError("Unknown OS {}".format(os.name))

# ffi.dlopen() may fail when playing with the wordsize (-m32)
if initial_cc and (' -m32' in initial_cc or ' -m64' in initial_cc):
    try:
        _cffi_example = ffi.dlopen(filepath)
    except OSError as exc:
        print(exc)
        print("... skipping the test with {}".format(os.path.basename(filepath)))
        _cffi_example = None
else:
    _cffi_example = ffi.dlopen(filepath)

if _cffi_example is not None:
    print(ffi.string(_cffi_example.helloworld).decode('utf-8'))
    print("The answer is {}".format(_cffi_example.get_answer()))


    # Using stringpair requires weak references
    global_weakkeydict = weakref.WeakKeyDictionary()


    def new_stringpair(str1, str2):
        """Create a new stringpair structure"""
        spair = ffi.new('struct stringpair*')
        s1 = ffi.new('char[]', str1.encode('utf-8'))
        s2 = ffi.new('char[]', str2.encode('utf-8'))
        spair.str1 = s1
        spair.str2 = s2
        global_weakkeydict[spair] = (s1, s2)
        return spair

    stringpair = new_stringpair('string one', 'string two')
    print("String pair: '{}', '{}'".format(
        ffi.string(stringpair.str1).decode('utf-8'),
        ffi.string(stringpair.str2).decode('utf-8')))
