#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2018 Nicolas Iooss
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Work on vectors from GF(2) = Z/2Z, to solve some linear equations

These functions are useful when working on some cryptography CTF contests,
where the encryption function is either linear (f(x^y) = f(x)^f(y)) or affine
(f(x^y)^f(0) = f(x)^f(y)).

For example RTFM Sigsegv1 Finals included such a challenge:
https://github.com/Read-The-Fancy-Manual/Finale-2018/tree/master/License_5
"""
import binascii
import functools
import itertools
import hashlib

try:
    import sage.all
    HAVE_SAGE = True
except ImportError:
    HAVE_SAGE = False
else:
    # GF(2) = Z/2Z = {0, 1}
    GF2 = sage.all.Zmod(2)


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    return int(binascii.hexlify(data).decode('ascii'), 16)


def encode_bigint_be(value, bytelen=None):
    """Encode a Big-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    hexval = '{{:0{:d}x}}'.format(bytelen * 2).format(value)
    return binascii.unhexlify(hexval.encode('ascii'))


def decode_bigint_bitvec(bitvec):
    """Decode a Bit-Endian integer from a vector of bits"""
    return int(''.join(str(bit) for bit in bitvec), 2)


def encode_bigint_bitvec(value, bitlen=None):
    """Encode a Bit-Endian integer into a vector of bits"""
    if bitlen is None:
        bitlen = value.bit_length()
    binval = '{{:0{:d}b}}'.format(bitlen).format(value)
    return [int(x) for x in binval]


assert decode_bigint_bitvec([0, 1, 0, 0]) == 4
assert encode_bigint_bitvec(42, 8) == [0, 0, 1, 0, 1, 0, 1, 0]


def triangulate_vectors(basis):
    """Compute a new basis for the linear span of the given basis using Gauss' Pivot

    Returns the new basis and the set of indices from the original one
    """
    new_basis = [vector for vector in basis]
    new_basis_idx = [set([i]) for i in range(len(basis))]
    for idx_progress in range(len(basis) - 1):
        mask = (1 << (idx_progress + 1)) - 1
        # Find a candidate
        idx_candidate = idx_progress
        while idx_candidate < len(basis) and (new_basis[idx_candidate] & mask) == 0:
            idx_candidate += 1
        if idx_candidate >= len(basis):
            # Every vector is zero for this bit
            continue

        # Switch items
        new_basis[idx_progress], new_basis[idx_candidate] = \
            new_basis[idx_candidate], new_basis[idx_progress]
        new_basis_idx[idx_progress], new_basis_idx[idx_candidate] = \
            new_basis_idx[idx_candidate], new_basis_idx[idx_progress]

        # Nullify a coordinate from the remaining vectors
        for idx_remove in range(idx_progress + 1, len(basis)):
            if new_basis[idx_remove] & mask:
                new_basis[idx_remove] ^= new_basis[idx_progress]
                new_basis_idx[idx_remove] = \
                    new_basis_idx[idx_remove].symmetric_difference(new_basis_idx[idx_progress])

    return new_basis, new_basis_idx


def diagonalize_vectors(basis):
    """Diagnalize a basis and return a list of set of indexes to get each bit"""
    new_basis, new_basis_idx = triangulate_vectors(basis)
    for idx_progress in range(len(basis)):
        for bit in range(idx_progress + 1, len(basis)):
            if (new_basis[idx_progress] >> bit) & 1:
                new_basis[idx_progress] ^= new_basis[bit]
                new_basis_idx[idx_progress] = new_basis_idx[idx_progress].symmetric_difference(new_basis_idx[bit])

    assert all(new_basis[i] == 1 << i for i in range(len(basis)))
    return new_basis_idx


def is_collinear(vector, basis):
    """Does the vector belongs to the linear span of basis in a GF(2)-space?

    Returns None if it does not, or a set of indices in the basis if it does
    """
    # Triangulate the basis
    new_basis, new_basis_idx = triangulate_vectors(basis)
    vector_idx = set()
    for i in range(len(basis)):
        if vector & new_basis[i] & (1 << i):
            vector ^= new_basis[i]
            vector_idx = vector_idx.symmetric_difference(new_basis_idx[i])
    return None if vector else vector_idx


def is_collinear_with_sage(vector, basis):
    """Implement is_collinear with sage"""
    bitlen = max(v.bit_length() for v in itertools.chain(basis, [vector]))
    sage_basis = [encode_bigint_bitvec(v, bitlen) for v in basis]
    sage_basis.append(encode_bigint_bitvec(vector, bitlen))
    mat_rank = sage.all.matrix(GF2, sage_basis).rank()
    return mat_rank != len(basis) + 1


def check_sha_base(bitsize):
    """Use a base made of SHA-2 hashes"""
    hash_functions = {
        256: hashlib.sha256,
        384: hashlib.sha384,
        512: hashlib.sha512,
    }
    hash_function = hash_functions[bitsize]
    print("Checking basis with SHA-{}".format(bitsize))

    basis_counters = []
    basis = []
    triangular_basis = []
    counter = 0
    while len(basis) != bitsize:
        test_vector_bytes = hash_function(str(counter).encode('ascii')).digest()
        test_vector_int = decode_bigint_be(test_vector_bytes)
        if is_collinear(test_vector_int, triangular_basis):
            counter += 1
            continue
        basis_counters.append(counter)
        basis.append(test_vector_int)
        triangular_basis.append(test_vector_int)
        triangular_basis = triangulate_vectors(triangular_basis)[0]
        counter += 1
    print("... Found basis after {} tests".format(counter))

    diag_basis_idx = diagonalize_vectors(basis)

    # Check that the algorithm worked
    for bitpos in range(bitsize):
        basis_vectors = [basis[idx] for idx in diag_basis_idx[bitpos]]
        value = functools.reduce(lambda x, y: x ^ y, basis_vectors)
        assert value == (1 << bitpos)

    # Use Sage if available
    if HAVE_SAGE:
        print("... Inverting the matrix with Sage")
        encoded_basis = [encode_bigint_bitvec(v, bitsize) for v in basis]
        sage_basis = sage.all.matrix(GF2, encoded_basis).transpose()
        assert sage_basis.rank() == bitsize
        # sage_basis * [1 0 0 0 0].transpose() = basis[0]
        # sage_basis * [0 1 0 0 0].transpose() = basis[1]
        # etc.
        # Now invert the basis
        sage_inv = sage_basis.inverse()
        test_vect = sage_inv * sage.all.matrix(GF2, encoded_basis[0]).transpose()
        assert test_vect[0][0] == 1
        assert all(test_vect[i][0] == 0 for i in range(1, bitsize))

        # Convert diag_basis_idx to a matrix
        mat_for_diag_basis_idx_values = [[0] * bitsize for _ in range(bitsize)]
        for bitpos in range(bitsize):
            for idx in diag_basis_idx[bitpos]:
                mat_for_diag_basis_idx_values[idx][bitsize - bitpos - 1] = 1
        mat_for_diag_basis_idx = sage.all.matrix(GF2, mat_for_diag_basis_idx_values)
        assert mat_for_diag_basis_idx == sage_inv

    # Compute the coordinates for a given test vector
    test_message = b'Hello, world!'
    test_vector = decode_bigint_be(test_message)
    test_indexes = set()
    for bitpos in range(bitsize):
        if (test_vector >> bitpos) & 1:
            test_indexes = test_indexes.symmetric_difference(diag_basis_idx[bitpos])

    linear_result = functools.reduce(lambda x, y: x ^ y, [basis[idx] for idx in test_indexes])
    linear_result_bytes = encode_bigint_be(linear_result)
    print("Obtained {} by combining {} SHA-{} digests".format(
        repr(linear_result_bytes), len(test_indexes), bitsize))
    assert linear_result_bytes == test_message


if __name__ == '__main__':
    if not HAVE_SAGE:
        print("Module sage was not found. Package sagemath may not be installed or compatible with this Python")
    check_sha_base(256)
    # check_sha_base(384)
    # check_sha_base(512)
