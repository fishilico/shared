#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Example of interaction between C code and numpy using cffi

@author: Nicolas Iooss
"""
from cffi import FFI
import numpy
import os.path

ffi = FFI()
current_dir = os.path.dirname(__file__) or os.path.curdir
with open(os.path.join(current_dir, 'cffi_example.h'), 'r') as fhead:
    ffi.cdef(''.join([
        line.replace('CFFI_EXAMPLE_API', '')
        for line in fhead if not line.lstrip().startswith('#')]))
_cffi_example = ffi.dlopen(os.path.join(current_dir, '_cffi_example.so'))

matrix = numpy.zeros((10, 10))
print("Original matrix:\n{}".format(matrix))

matrix_data = ffi.cast("double *", matrix.ctypes.data)
_cffi_example.matrix_add_coords(matrix_data, matrix.shape[0], matrix.shape[1])
print("Matrix after add_coords:\n{}".format(matrix))

_cffi_example.transpose_square_matrix(matrix_data, matrix.shape[0])
print("Transposed matrix:\n{}".format(matrix))
