#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""Example of interaction between C code and numpy using cffi

@author: Nicolas Iooss
"""
from cffi import FFI
import numpy
import os
import os.path
import sys

ffi = FFI()
SIZEOF_DOUBLE = ffi.sizeof('double')
current_dir = os.path.dirname(__file__) or os.path.curdir
with open(os.path.join(current_dir, 'cffi_example.h'), 'r') as fhead:
    ffi.cdef(''.join([
        line.replace('CFFI_EXAMPLE_API', '')
        for line in fhead if not line.lstrip().startswith('#')]))
filepath = os.path.join(current_dir, '_cffi_example')
if os.name == 'nt':
    filepath += '.dll'
elif os.name == 'posix':
    filepath += '.so'
else:
    raise RuntimeError("Unknown OS {}".format(os.name))

env_cc = os.environ.get('CC')
if env_cc and (' -m32' in env_cc or ' -m64' in env_cc):
    try:
        _cffi_example = ffi.dlopen(filepath)
    except OSError as exc:
        print(exc)
        print("... skipping the test")
        _cffi_example = None
else:
    _cffi_example = ffi.dlopen(filepath)


def get_matrix_stride(mat):
    """Get the stride between lines of a C matrix"""
    itemsize = mat.itemsize
    stride = mat.strides[0] // itemsize
    assert mat.strides == (stride * itemsize, itemsize)
    return stride


def check_double_matrix(mat):
    """Check that the matrix of double looks fine"""
    if len(mat.shape) != 2:
        sys.stderr.write("Invalid matrix: dimension {} not {}\n"
                         .format(len(mat.shape), 2))
        return False

    # If the strides hasn't got the same number of elements, really weird
    # things happened... Let's abort in such case
    assert len(mat.strides) == len(mat.shape)

    if mat.itemsize != SIZEOF_DOUBLE:
        sys.stderr.write("Invalid matrix: item size {} not {}\n"
                         .format(mat.itemsize, SIZEOF_DOUBLE))
        return False

    if mat.strides[0] < mat.strides[1] or mat.strides[1] != mat.itemsize:
        sys.stderr.write("Invalid strides for a C matrix: {}\n"
                         .format(mat.strides))
        return False

    # If itemsize couldn't divide the stride, nothing would work...
    assert (mat.strides[0] % mat.itemsize) == 0

    if mat.strides[0] < mat.shape[1] * mat.strides[1]:
        sys.stderr.write("Too small strides for shape: {} < {}\n"
                         .format(mat.strides[0], mat.shape[1] * mat.strides[1]))
        return False
    return True


def main():
    """Test several things around numpy and cffi"""
    matrix = numpy.zeros((10, 10))
    print("Original matrix:\n{}".format(matrix))
    if not check_double_matrix(matrix):
        return 1

    matrix_data = ffi.cast("double *", matrix.ctypes.data)
    _cffi_example.matrix_add_coords(matrix_data,
                                    matrix.shape[0], matrix.shape[1])
    print("Matrix after add_coords:\n{}".format(matrix))
    if not check_double_matrix(matrix):
        return 1

    _cffi_example.transpose_square_matrix(matrix_data, matrix.shape[0])
    print("Transposed matrix:\n{}".format(matrix))
    if not check_double_matrix(matrix):
        return 1

    submatrix = matrix[2:7, 2:7]
    if not check_double_matrix(submatrix):
        sys.stderr.write("Invalid submatrix\n")
        return 1

    _cffi_example.scalar_mul_matrix(
        ffi.cast("double *", submatrix.ctypes.data),
        submatrix.shape[0], submatrix.shape[1],
        get_matrix_stride(submatrix), -1)
    print("Matrix after sub-matrix multiplication by -1:\n{}".format(matrix))
    if not check_double_matrix(matrix):
        return 1
    return 0


if __name__ == '__main__':
    if _cffi_example is not None:
        sys.exit(main())
