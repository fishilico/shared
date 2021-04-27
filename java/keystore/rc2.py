#!/usr/bin/env python
"""
RC2 implementation based on
https://github.com/0xEBFE/RC2-python/blob/master/rc2.py

This is needed because Cryptodome.Cipher.ARC2 does not work properly when using
40-bit keys: https://github.com/Legrandin/pycryptodome/issues/267
"""
import array
import struct
import sys


RC2_BLOCK_SIZE = 8
MODE_ECB = 0
MODE_CBC = 1
PADDING_PKCS5 = 1


def ROL16(x, n):
    return ((x << n) | (x >> (16 - n))) & 0xFFFF


def ROR16(x, n):
    return ((x >> n) | (x << (16 - n))) & 0xFFFF


# byte-ord
bord = (lambda x: x) if sys.version_info >= (3,) else ord


class RC2():

    def __init__(self, key):

        sbox = array.array('B', [
            0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
            0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
            0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
            0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
            0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C, 0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
            0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
            0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
            0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
            0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
            0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
            0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
            0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
            0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
            0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C, 0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
            0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
            0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD])

        rc2_key = bytearray(128)

        for i in range(128):
            if len(key) > i:
                rc2_key[i] = key[i]
            else:
                rc2_key[i] = sbox[rc2_key[i-1] + rc2_key[i - len(key)] & 0xFF]

        rc2_key[128 - len(key)] = sbox[rc2_key[128 - len(key)]]

        if len(key) < 128:
            for i in range(127 - len(key), -1, -1):
                xor = rc2_key[i + 1] ^ rc2_key[len(key) + i]
                rc2_key[i] = sbox[xor & 0xFF]

        self.K = struct.unpack('<64H', bytes(rc2_key))

    def encrypt_mixup(self, K, x0, x1, x2, x3, round):

        j = round * 4
        x0 = (x0 + (x2 & x3) + (~x3 & x1) + K[j]) & 0xFFFF
        x0 = ROL16(x0, 1)
        j += 1

        x1 = (x1 + (x3 & x0) + (~x0 & x2) + K[j]) & 0xFFFF
        x1 = ROL16(x1, 2)
        j += 1

        x2 = (x2 + (x0 & x1) + (~x1 & x3) + K[j]) & 0xFFFF
        x2 = ROL16(x2, 3)
        j += 1

        x3 = (x3 + (x1 & x2) + (~x2 & x0) + K[j]) & 0xFFFF
        x3 = ROL16(x3, 5)

        return x0, x1, x2, x3

    def decrypt_mixup(self, K, x0, x1, x2, x3, round):

        j = round * 4 + 3
        x3 = ROR16(x3, 5)
        x3 = (x3 - (x1 & x2) - (~x2 & x0) - K[j]) & 0xFFFF
        j -= 1

        x2 = ROR16(x2, 3)
        x2 = (x2 - (x0 & x1) - (~x1 & x3) - K[j]) & 0xFFFF
        j -= 1

        x1 = ROR16(x1, 2)
        x1 = (x1 - (x3 & x0) - (~x0 & x2) - K[j]) & 0xFFFF
        j -= 1

        x0 = ROR16(x0, 1)
        x0 = (x0 - (x2 & x3) - (~x3 & x1) - K[j]) & 0xFFFF

        return x0, x1, x2, x3

    def encrypt_mash(self, K, x0, x1, x2, x3):

        x0 = (x0 + K[x3 & 63]) & 0xFFFF
        x1 = (x1 + K[x0 & 63]) & 0xFFFF
        x2 = (x2 + K[x1 & 63]) & 0xFFFF
        x3 = (x3 + K[x2 & 63]) & 0xFFFF

        return x0, x1, x2, x3

    def decrypt_mash(self, K, x0, x1, x2, x3):

        x3 = (x3 - K[x2 & 63]) & 0xFFFF
        x2 = (x2 - K[x1 & 63]) & 0xFFFF
        x1 = (x1 - K[x0 & 63]) & 0xFFFF
        x0 = (x0 - K[x3 & 63]) & 0xFFFF

        return x0, x1, x2, x3

    def block_encrypt(self, input_buffer):

        R = list(struct.unpack('<4H', input_buffer))

        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 0)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 1)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 2)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 3)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 4)

        R[0], R[1], R[2], R[3] = self.encrypt_mash(self.K, R[0], R[1], R[2], R[3])

        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 5)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 6)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 7)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 8)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 9)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 10)

        R[0], R[1], R[2], R[3] = self.encrypt_mash(self.K, R[0], R[1], R[2], R[3])

        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 11)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 12)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 13)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 14)
        R[0], R[1], R[2], R[3] = self.encrypt_mixup(self.K, R[0], R[1], R[2], R[3], 15)

        return struct.pack('<4H', *R)

    def block_decrypt(self, input_buffer):

        R = list(struct.unpack('<4H', input_buffer))

        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 15)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 14)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 13)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 12)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 11)

        R[0], R[1], R[2], R[3] = self.decrypt_mash(self.K, R[0], R[1], R[2], R[3])

        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 10)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 9)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 8)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 7)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 6)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 5)

        R[0], R[1], R[2], R[3] = self.decrypt_mash(self.K, R[0], R[1], R[2], R[3])

        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 4)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 3)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 2)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 1)
        R[0], R[1], R[2], R[3] = self.decrypt_mixup(self.K, R[0], R[1], R[2], R[3], 0)

        return struct.pack('<4H', *R)

    def encrypt(self, input_buffer, mode, iv=None, padding=None):

        if (len(input_buffer) % RC2_BLOCK_SIZE) == 0 and padding != PADDING_PKCS5:
            crypt_size = len(input_buffer)
        else:
            crypt_size = ((len(input_buffer) // RC2_BLOCK_SIZE) + 1) * RC2_BLOCK_SIZE

        crypt_buffer = bytearray(crypt_size)

        for i in range(crypt_size):
            if len(input_buffer) > i:
                crypt_buffer[i] = input_buffer[i]
            elif padding == PADDING_PKCS5:
                crypt_buffer[i] = (RC2_BLOCK_SIZE - (len(input_buffer) % RC2_BLOCK_SIZE)) & 0xFF

        result = bytearray()
        block_result = None
        for block_counter in range(crypt_size//RC2_BLOCK_SIZE):

            block = crypt_buffer[block_counter * RC2_BLOCK_SIZE:block_counter * RC2_BLOCK_SIZE + RC2_BLOCK_SIZE]

            if block_counter == 0:
                if mode == MODE_CBC and iv is not None:
                    for i in range(RC2_BLOCK_SIZE):
                        block[i] = block[i] ^ bord(iv[i])
            else:
                if mode == MODE_CBC:
                    for i in range(RC2_BLOCK_SIZE):
                        block[i] = block[i] ^ bord(block_result[i])

            block_result = self.block_encrypt(bytes(block))

            result += block_result

        return bytes(result)

    def decrypt(self, input_buffer, mode, iv=None, padding=None):

        crypt_size = len(input_buffer)
        crypt_buffer = bytearray(crypt_size)

        for i in range(crypt_size):
            crypt_buffer[i] = input_buffer[i]

        previous_block = None
        for block_counter in range(crypt_size//RC2_BLOCK_SIZE):

            block = crypt_buffer[block_counter * RC2_BLOCK_SIZE:block_counter * RC2_BLOCK_SIZE + RC2_BLOCK_SIZE]

            block_result = self.block_decrypt(bytes(block))

            if mode == MODE_CBC:
                if block_counter == 0:
                    if iv is not None:
                        for i in range(RC2_BLOCK_SIZE):
                            crypt_buffer[block_counter * RC2_BLOCK_SIZE + i] = bord(block_result[i]) ^ bord(iv[i])
                else:
                    for i in range(RC2_BLOCK_SIZE):
                        crypt_buffer[block_counter * RC2_BLOCK_SIZE + i] = bord(block_result[i]) ^ previous_block[i]
            else:
                for i in range(RC2_BLOCK_SIZE):
                    crypt_buffer[block_counter * RC2_BLOCK_SIZE + i] = bord(block_result[i])

            previous_block = block

        if padding == PADDING_PKCS5:
            crypt_buffer = crypt_buffer[:-crypt_buffer[crypt_size - 1]]
        return bytes(crypt_buffer)


def main():
    rc2 = RC2(bytearray((00, 00, 00, 00, 00, 00, 00, 00)))
    test1 = bytearray((0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22))
    out1 = rc2.encrypt(test1, MODE_CBC, b'12345678', PADDING_PKCS5)

    assert out1 == \
        bytearray((0x52, 0x19, 0x04, 0x0C, 0x47, 0x80, 0x5D, 0xBE, 0xA7, 0xB6, 0x7C, 0xEF, 0x26, 0xEF, 0x60, 0x80))
    assert test1 == rc2.decrypt(out1, MODE_CBC, b'12345678', PADDING_PKCS5)

    rc2 = RC2(bytearray((00, 00, 00, 00, 00, 00, 00, 00)))
    test2 = bytearray((00, 00, 00, 00, 00, 00, 00, 00))
    out2 = rc2.encrypt(test2, MODE_ECB)
    assert out2 == bytearray((0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff))
    assert test2 == rc2.decrypt(out2, MODE_ECB)

    rc2 = RC2(bytearray((0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)))
    test3 = bytearray((0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))
    out3 = rc2.encrypt(test3, MODE_ECB)
    assert out3 == bytearray((0x27, 0x8b, 0x27, 0xe4, 0x2e, 0x2f, 0x0d, 0x49))
    assert test3 == rc2.decrypt(out3, MODE_ECB)

    # Compare with PyCrypto implementation
    try:
        import Cryptodome.Cipher.ARC2
    except ImportError:
        pass
    else:
        key = b'12345678'
        plaintext = b'\0' * 8
        crypto_rc2 = Cryptodome.Cipher.ARC2.new(key, Cryptodome.Cipher.ARC2.MODE_ECB, effective_keylen=len(key) * 8)
        encrypted_pycrypto = crypto_rc2.encrypt(plaintext)

        rc2 = RC2(key)
        encrypted_custom = rc2.encrypt(plaintext, MODE_ECB)
        assert encrypted_pycrypto == encrypted_custom


if __name__ == '__main__':
    main()
