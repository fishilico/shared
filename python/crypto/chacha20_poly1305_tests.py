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
"""Study ChaCha20-Poly1305 and mathematic properties

IMPORTANT NOTICE: these implementations are NOT secure, for example regarding
timing attacks. DO NOT USE THEM IN PRODUCTION. They may only be useful when
studying labs or test cases of cyrptography, to understand how a protocol
encrypts data for example.

Documentation:
* https://cr.yp.to/rumba20/newfeatures-20071218.pdf
  New Features of Latin Dances: Analysis of Salsa, ChaCha, and Rumba
* https://tools.ietf.org/html/rfc7539
  RFC 7539: ChaCha20 and Poly1305 for IETF protocols
* http://www.bortzmeyer.org/7539.html
  Comment on RFC 7539 (2015-05-15)
"""
import binascii
import errno
import os
import struct
import subprocess
import sys


try:
    import Crypto.Cipher.ChaCha20 as CryptoChaCha20
    has_crypto = True
except ImportError:
    try:
        # On Ubuntu, python3-pycryptodome installs in Cryptodome module
        import Cryptodome.Cipher.ChaCha20 as CryptoChaCha20
        has_crypto = True
    except ImportError:
        sys.stderr.write("Warning: PyCrypto fails to load. Proceeding without it\n")
        has_crypto = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.backends import default_backend
    has_cryptography = True
except ImportError:
    sys.stderr.write("Warning: cryptography fails to load. Proceeding without it\n")
    has_cryptography = False


# Poly1305 prime
POLY1305_PRIME = (1 << 130) - 5
assert POLY1305_PRIME == 0x3fffffffffffffffffffffffffffffffb


def rol32(x, shift):
    """Rotate X left by the given shift value"""
    assert 0 < shift < 32
    return (x >> (32 - shift)) | ((x << shift) & 0xffffffff)


def xx(data):
    """One-line hexadecimal representation of binary data"""
    if sys.version_info < (3, 5):
        return binascii.hexlify(data).decode('ascii')
    return data.hex()


def chacha_quarter_round(a, b, c, d):
    """Perform a quarter round for ChaCha20"""
    # a += b; d ^= a; d <<<= 16;
    a = (a + b) & 0xffffffff
    d ^= a
    d = rol32(d, 16)

    # c += d; b ^= c; b <<<= 12;
    c = (c + d) & 0xffffffff
    b ^= c
    b = rol32(b, 12)

    # a += b; d ^= a; d <<<= 8;
    a = (a + b) & 0xffffffff
    d ^= a
    d = rol32(d, 8)

    # c += d; b ^= c; b <<<= 7;
    c = (c + d) & 0xffffffff
    b ^= c
    b = rol32(b, 7)
    return a, b, c, d


def chacha_initial_state(key, block_count, nonce):
    """Initialize a 4x4 32-bit state matrix from parameters

    The resulting matrix is a list of 16 integer of 32 bits each:

        0   1   2   3
        4   5   6   7
        8   9  10  11
       12  13  14  15
    """
    assert len(key) == 32  # key is 256-bit wide
    assert 0 <= block_count <= 0xffffffff  # block count is 32-byte wide
    assert len(nonce) == 12  # nonce is 96-bit wide

    key_l = struct.unpack('<IIIIIIII', key)
    nonce_l = struct.unpack('<III', nonce)
    return [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  # 'expand 32-byte k'
        key_l[0], key_l[1], key_l[2], key_l[3],
        key_l[4], key_l[5], key_l[6], key_l[7],
        block_count, nonce_l[0], nonce_l[1], nonce_l[2],
    ]


def chacha_column_round(st):
    """Perform a column round of ChaCha20 on the state"""
    st[0], st[4], st[8], st[12] = chacha_quarter_round(st[0], st[4], st[8], st[12])
    st[1], st[5], st[9], st[13] = chacha_quarter_round(st[1], st[5], st[9], st[13])
    st[2], st[6], st[10], st[14] = chacha_quarter_round(st[2], st[6], st[10], st[14])
    st[3], st[7], st[11], st[15] = chacha_quarter_round(st[3], st[7], st[11], st[15])


def chacha_diagonal_round(st):
    """Perform a diagonal round of ChaCha20 on the state"""
    st[0], st[5], st[10], st[15] = chacha_quarter_round(st[0], st[5], st[10], st[15])
    st[1], st[6], st[11], st[12] = chacha_quarter_round(st[1], st[6], st[11], st[12])
    st[2], st[7], st[8], st[13] = chacha_quarter_round(st[2], st[7], st[8], st[13])
    st[3], st[4], st[9], st[14] = chacha_quarter_round(st[3], st[4], st[9], st[14])


def chacha20_block(key, block_count, nonce):
    """Compute a ChaCha20 block (64 bytes = 512 bits) from parameters"""
    initial_state = chacha_initial_state(key, block_count, nonce)
    state = [x for x in initial_state]
    for _i_round in range(10):
        chacha_column_round(state)
        chacha_diagonal_round(state)
    for i in range(16):
        state[i] = (state[i] + initial_state[i]) & 0xffffffff
    return struct.pack('<IIIIIIIIIIIIIIII', *state)


def chacha20_crypt(key, counter, nonce, plaintext):
    """Encrypt or decrypt data using ChaCha20"""
    encrypted = bytearray(len(plaintext))
    for stream_offset in range(0, len(plaintext), 64):
        block_index = stream_offset // 64
        key_stream = chacha20_block(key, counter + block_index, nonce)
        for i in range(min(64, len(plaintext) - stream_offset)):
            if sys.version_info < (3,):
                encrypted[stream_offset + i] = ord(plaintext[stream_offset + i]) ^ ord(key_stream[i])
            else:
                encrypted[stream_offset + i] = plaintext[stream_offset + i] ^ key_stream[i]
    return bytes(encrypted)


def check_chacha20_test_vectors():
    """Check Chacha20 test vectors from several sources"""
    print("Checking ChaCha20 test vectors")

    # https://tools.ietf.org/html/rfc7539#section-2.1.1
    qround_out = chacha_quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567)
    assert qround_out == (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)

    # https://tools.ietf.org/html/rfc7539#section-2.2.1
    qround_out = chacha_quarter_round(0x516461b1, 0x2a5f714c, 0x53372767, 0x3d631689)
    assert qround_out == (0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79)

    # https://tools.ietf.org/html/rfc7539#section-2.3.2
    key = b''.join(struct.pack('B', i) for i in range(32))
    nonce = b'\0\0\0\x09\0\0\0\x4a\0\0\0\0'
    block = chacha20_block(key, 1, nonce)
    expected_block = binascii.unhexlify(
        '10f1e7e4d13b5915500fdd1fa32071c4' +
        'c7d1f4c733c068030422aa9ac3d46c4e' +
        'd2826446079faa0914c2d705d98b02a2' +
        'b5129cd1de164eb9cbd083e8a2503c4e')
    assert block == expected_block

    # https://tools.ietf.org/html/rfc7539#section-2.4.2
    key = b''.join(struct.pack('B', i) for i in range(32))
    nonce = b'\0\0\0\0\0\0\0\x4a\0\0\0\0'
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: " +
        b"If I could offer you only one tip for the future, sunscreen would be it.")
    encrypted = chacha20_crypt(key, 1, nonce, plaintext)
    expected_encrypted = binascii.unhexlify(
        '6e2e359a2568f98041ba0728dd0d6981' +
        'e97e7aec1d4360c20a27afccfd9fae0b' +
        'f91b65c5524733ab8f593dabcd62b357' +
        '1639d624e65152ab8f530c359f0861d8' +
        '07ca0dbf500d6a6156a38e088a22b65e' +
        '52bc514d16ccf806818ce91ab7793736' +
        '5af90bbf74a35be6b40b8eedf2785e42' +
        '874d')
    assert encrypted == expected_encrypted
    decrypted = chacha20_crypt(key, 1, nonce, encrypted)
    assert decrypted == plaintext

    # https://tools.ietf.org/html/rfc7539#appendix-A.1
    block = chacha20_block(key=b'\0' * 32, block_count=0, nonce=b'\0' * 12)
    expected_block = binascii.unhexlify(
        '76b8e0ada0f13d90405d6ae55386bd28' +
        'bdd219b8a08ded1aa836efcc8b770dc7' +
        'da41597c5157488d7724e03fb8d84a37' +
        '6a43b8f41518a11cc387b669b2ee6586')
    assert block == expected_block

    block = chacha20_block(key=b'\0' * 32, block_count=1, nonce=b'\0' * 12)
    expected_block = binascii.unhexlify(
        '9f07e7be5551387a98ba977c732d080d' +
        'cb0f29a048e3656912c6533e32ee7aed' +
        '29b721769ce64e43d57133b074d839d5' +
        '31ed1f28510afb45ace10a1f4b794d6f')
    assert block == expected_block

    block = chacha20_block(key=b'\0' * 31 + b'\x01', block_count=1, nonce=b'\0' * 12)
    expected_block = binascii.unhexlify(
        '3aeb5224ecf849929b9d828db1ced4dd' +
        '832025e8018b8160b82284f3c949aa5a' +
        '8eca00bbb4a73bdad192b5c42f73f2fd' +
        '4e273644c8b36125a64addeb006c13a0')
    assert block == expected_block

    block = chacha20_block(key=b'\0\xff' + b'\0' * 30, block_count=2, nonce=b'\0' * 12)
    expected_block = binascii.unhexlify(
        '72d54dfbf12ec44b362692df94137f32' +
        '8fea8da73990265ec1bbbea1ae9af0ca' +
        '13b25aa26cb4a648cb9b9d1be65b2c09' +
        '24a66c54d545ec1b7374f4872e99f096')
    assert block == expected_block

    block = chacha20_block(key=b'\0' * 32, block_count=0, nonce=b'\0' * 11 + b'\x02')
    expected_block = binascii.unhexlify(
        'c2c64d378cd536374ae204b9ef933fcd' +
        '1a8b2288b3dfa49672ab765b54ee27c7' +
        '8a970e0e955c14f3a88e741b97c286f7' +
        '5f8fc299e8148362fa198a39531bed6d')
    assert block == expected_block

    if has_crypto:
        # Test encrypting/decrypting random data
        print("Checking ChaCha20 implementation vs. PyCrypto(dome)")
        key = os.urandom(32)
        nonce = os.urandom(8)  # PyCryptodome only supports 64-bit nonce
        plaintext = os.urandom(96)
        crypto_chacha20 = CryptoChaCha20.new(key=key, nonce=nonce)
        encrypted = chacha20_crypt(key, 0, b'\0\0\0\0' + nonce, plaintext)
        assert crypto_chacha20.encrypt(plaintext) == encrypted, \
            "Problem encrypting with key={}, nonce={}, plain={}".format(xx(key), xx(nonce), xx(plaintext))

        crypto_chacha20 = CryptoChaCha20.new(key=key, nonce=nonce)
        decrypted = chacha20_crypt(key, 0, b'\0\0\0\0' + nonce, encrypted)
        assert crypto_chacha20.decrypt(encrypted) == decrypted, \
            "Problem decrypting with key={}, nonce={}, encrypted={}".format(xx(key), xx(nonce), xx(encrypted))

    if has_cryptography:
        # Test encrypting/decrypting random data
        print("Checking ChaCha20 implementation vs. Cryptography.io")
        key = os.urandom(32)
        block_counter = os.urandom(4)
        nonce = os.urandom(12)
        plaintext = os.urandom(96)
        block_counter_int, = struct.unpack('<I', block_counter)
        cipher = Cipher(algorithms.ChaCha20(key, block_counter + nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = chacha20_crypt(key, block_counter_int, nonce, plaintext)
        assert encryptor.update(plaintext) == encrypted, \
            "Problem encrypting with key={}, bc={}, nonce={}, plain={}".format(
                xx(key), xx(block_counter), xx(nonce), xx(plaintext))
        assert encryptor.finalize() == b''

        decryptor = cipher.decryptor()
        decrypted = chacha20_crypt(key, block_counter_int, nonce, encrypted)
        assert decryptor.update(encrypted) == decrypted, \
            "Problem decrypting with key={}, bc={}, nonce={}, encrypted={}".format(
                xx(key), xx(block_counter), xx(nonce), xx(encrypted))
        assert decryptor.finalize() == b''


def poly1305_mac(msg, key):
    """Compute the Poly1305 Message Authentication Code (MAC) of the given message"""
    assert len(key) == 32  # key is 32-byte key
    r_low, r_high, s_low, s_high = struct.unpack('<QQQQ', key)
    r = r_low | (r_high << 64)
    s = s_low | (s_high << 64)

    # Clamp r
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    accumulator = 0

    for offset in range(0, len(msg), 16):
        chunk = msg[offset:offset + 16]
        n_bytes = struct.unpack('B' * len(chunk), chunk)
        n = sum(x << (8 * i) for i, x in enumerate(n_bytes))
        n |= 1 << (8 * len(n_bytes))
        accumulator = ((accumulator + n) * r) % POLY1305_PRIME
    accumulator += s

    # Convert the accumulator to 16 bytes in little endian
    result = bytearray(16)
    for i in range(16):
        result[i] = accumulator & 0xff
        accumulator >>= 8
    return bytes(result)


def chacha20_poly1305_key_gen(key, nonce):
    """Generate a Poly1305 key from a MAC key and a nonce"""
    block = chacha20_block(key, 0, nonce)
    assert len(block) == 64
    return block[:32]


def check_poly1305_test_vectors():
    """Check Poly1305 test vectors"""
    print("Checking Poly1305 test vectors")

    # https://tools.ietf.org/html/rfc7539#section-2.5.2
    key = binascii.unhexlify('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
    msg = b'Cryptographic Forum Research Group'
    tag = poly1305_mac(msg, key)
    assert tag == binascii.unhexlify('a8061dc1305136c6c22b8baf0c0127a9')

    # https://tools.ietf.org/html/rfc7539#section-2.6.2
    key = b''.join(struct.pack('B', 0x80 + i) for i in range(32))
    nonce = binascii.unhexlify('000000000001020304050607')
    poly1305_key = chacha20_poly1305_key_gen(key, nonce)
    assert poly1305_key == binascii.unhexlify(
        '8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646')

    # https://tools.ietf.org/html/rfc7539#appendix-A.4
    poly1305_key = chacha20_poly1305_key_gen(key=b'\0' * 32, nonce=b'\0' * 12)
    assert poly1305_key == binascii.unhexlify(
        '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7')

    poly1305_key = chacha20_poly1305_key_gen(key=b'\0' * 31 + b'\x01', nonce=b'\0' * 11 + b'\x02')
    assert poly1305_key == binascii.unhexlify(
        'ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739')

    key = binascii.unhexlify(
        '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0')
    poly1305_key = chacha20_poly1305_key_gen(key, nonce=b'\0' * 11 + b'\x02')
    assert poly1305_key == binascii.unhexlify(
        '965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae')


def chacha20_poly1305_aead_encrypt(aad, key, iv, constant, plaintext):
    """Encrypt data using Chacha20 Poly1305 AEAD

    aad: Additional Authenticated Data
    key: ChaCha20 key, also used of Poly1305 key
    iv: low 64 bits of nonce
    constant: high 32 bits of nonce (sender ID)
    plaintext: text to encrypt

    Returns:
    ciphertext: encrypted plaintext
    tag: Poly1305 tag
    """
    assert len(key) == 32
    assert len(iv) == 8
    nonce = struct.pack('<I', constant) + iv
    otk = chacha20_poly1305_key_gen(key, nonce)
    ciphertext = chacha20_crypt(key, 1, nonce, plaintext)
    mac_data = aad
    mac_data += b'\0' * ((16 - len(aad)) % 16)
    mac_data += ciphertext
    mac_data += b'\0' * ((16 - len(ciphertext)) % 16)
    mac_data += struct.pack('<QQ', len(aad), len(ciphertext))
    tag = poly1305_mac(mac_data, otk)
    return ciphertext, tag


def chacha20_poly1305_aead_decrypt(aad, key, iv, constant, ciphertext, tag):
    """Verify and decrypt data using Chacha20 Poly1305 AEAD"""
    assert len(key) == 32
    assert len(iv) == 8
    nonce = struct.pack('<I', constant) + iv
    otk = chacha20_poly1305_key_gen(key, nonce)
    mac_data = aad
    mac_data += b'\0' * ((16 - len(aad)) % 16)
    mac_data += ciphertext
    mac_data += b'\0' * ((16 - len(ciphertext)) % 16)
    mac_data += struct.pack('<QQ', len(aad), len(ciphertext))
    computed_tag = poly1305_mac(mac_data, otk)
    if tag != computed_tag:
        raise ValueError("Invalid AEAD tag")
    return chacha20_crypt(key, 1, nonce, ciphertext)


def check_chacha20_poly1305_test_vectors():
    """Check ChaCha20-Poly1305 test vectors"""
    print("Checking ChaCha20-Poly1305 test vectors")

    # https://tools.ietf.org/html/rfc7539#section-2.8.2
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: " +
        b"If I could offer you only one tip for the future, sunscreen would be it.")
    aad = binascii.unhexlify('50515253c0c1c2c3c4c5c6c7')
    key = b''.join(struct.pack('B', 0x80 + i) for i in range(32))
    iv = b'@ABCDEFG'
    sender_id = 7
    ciphertext, tag = chacha20_poly1305_aead_encrypt(aad, key, iv, sender_id, plaintext)
    expected_ciphertext = binascii.unhexlify(
        'd31a8d34648e60db7b86afbc53ef7ec2' +
        'a4aded51296e08fea9e2b5a736ee62d6' +
        '3dbea45e8ca9671282fafb69da92728b' +
        '1a71de0a9e060b2905d6a5b67ecd3b36' +
        '92ddbd7f2d778b8c9803aee328091b58' +
        'fab324e4fad675945585808b4831d7bc' +
        '3ff4def08e4b7a9de576d26586cec64b' +
        '6116')
    expected_tag = binascii.unhexlify('1ae10b594f09e26a7e902ecbd0600691')
    assert ciphertext == expected_ciphertext
    assert tag == expected_tag
    assert chacha20_poly1305_aead_decrypt(aad, key, iv, sender_id, ciphertext, tag) == plaintext

    if has_cryptography:
        print("Checking ChaCha20-Poly1305 implementation vs. Cryptography.io")
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = os.urandom(96)
        aad = os.urandom(96)
        sender_id, = struct.unpack('<I', nonce[:4])
        iv = nonce[4:]

        ciphertext, tag = chacha20_poly1305_aead_encrypt(aad, key, iv, sender_id, plaintext)
        assert len(tag) == 16
        chacha = ChaCha20Poly1305(key)
        assert chacha.encrypt(nonce, plaintext, aad) == ciphertext + tag, \
            "Problem encrypting with key={}, nonce={}, plain={}, aad={}".format(
                xx(key), xx(nonce), xx(plaintext), xx(aad))

        decrypted = chacha20_poly1305_aead_decrypt(aad, key, iv, sender_id, ciphertext, tag)
        assert chacha.decrypt(nonce, ciphertext + tag, aad) == decrypted, \
            "Problem decrypting with key={}, nonce={}, ciphertext={}, aad={}".format(
                xx(key), xx(nonce), xx(ciphertext), xx(aad))


def check_chacha20_openssl_with_keys(key, nonce, message):
    """Compare ChaCha20 with openssl command for a given message"""
    cmdline = [
        'openssl', 'enc', '-chacha20',
        '-K', xx(key),
        '-iv', xx(b'\0\0\0\0' + nonce),
    ]
    proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    proc.stdin.write(message)
    proc.stdin.close()
    output = proc.stdout.read()
    ret = proc.wait()
    if ret != 0:
        raise ValueError("openssl failed with error {}".format(ret))
    assert chacha20_crypt(key=key, counter=0, nonce=nonce, plaintext=message) == output


def check_chacha20_openssl():
    """Compare ChaCha20 with openssl command"""
    print("Checking openssl enc -chacha20")

    # Does OpenSSL know ChaCha20 yet?
    try:
        output = subprocess.check_output(['openssl', 'enc', '-ciphers'])
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            print("... command openssl not found, skipping test.")
            return
        raise
    except subprocess.CalledProcessError as exc:
        print("... openssl enc -ciphers exited with error 1, analyzing its output")
        output = exc.output

    if '-chacha20' not in output.decode('ascii').split():
        print("... openssl does not support ChaCha20, skipping test.")
        return

    # Zero key
    check_chacha20_openssl_with_keys(key=b'\0' * 32, nonce=b'\0' * 12, message=b'\0' * 64)
    # non-zero key
    check_chacha20_openssl_with_keys(key=b'K' * 32, nonce=b'N' * 12, message=b'M' * 442)
    # random
    key = os.urandom(32)
    nonce = os.urandom(12)
    message = os.urandom(96)
    try:
        check_chacha20_openssl_with_keys(key=key, nonce=nonce, message=message)
    except ValueError:
        print("Failure with key={}, nonce={}, message={}".format(key, nonce, message))


def study_chacha20_poly1305():
    """Perform some tests on Chach20 and Poly1305"""
    check_chacha20_test_vectors()
    check_poly1305_test_vectors()
    check_chacha20_poly1305_test_vectors()
    check_chacha20_openssl()


if __name__ == '__main__':
    study_chacha20_poly1305()
