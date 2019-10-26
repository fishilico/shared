/**
 * Find AES keys in files, detecting the expanded key
 *
 * Inspiration from:
 * - AES finder (https://github.com/mmozeiko/aes-finder)
 * - aeskeyfind (https://github.com/makomk/aeskeyfind)
 *
 * AES key expansion algorithm:
 * - Define constants:
 *      - Nb: Number of columns (32-bit words) comprising the State.
 *          Nb = 4
 *      - Nk: Number of 32-bit words comprising the Cipher Key
 *          Nk = 4 for AES128, 6 for AES192, 8 for AES256
 *      - Nr = Nk + 6: Number of rounds
 *          Nr = 10 for AES128, 12 for AES192, 14 for AES256
 * - Define functions:
 *      - RotWord(word) = ror32(word, 8)
 *      - SubWord(word) = map AES_SBOX to each byte for 32-bit word
 *      - InvMixColumn(word) = multiply word (as polynom in GF(2^8)[X]) with
 *          ({0b}X^3 + {0d}X^2 + {09}X + {0e}) modulo X^4+1
 * - Expand the key into W, which contains (Nr+1) 4-word tuples for encryption
 *      for i in 0..Nk:
 *          W[i] = key[4 * i:4 * i + 4] as 32-bit word
 *      for i in Nk..(Nb * (Nr + 1)):
 *          temp = W[i - 1]
 *          if (i % Nk) == 0:
 *              temp = SubWord(RotWord(temp))
 *              temp ^= AES_RCON[floor(i / Nk) - 1]
 *          else if AES256 and (i % Nk) == 4:
 *              temp = SubWord(temp)
 *          W[i] = W[i - Nk] ^ temp
 * - For optimised decryption, an other expanded key can be used
 *      for i in 0..Nb:
 *          DecW[i] = W[Nb * Nr + i]
 *      for i in (Nb * Nr)..(Nb * (Nr + 1)):
 *          DecW[i] = W[i - Nb * Nr]
 *      for i in Nb..(Nb * Nr):
 *          # j = 4 * Nr - (i & ~3) + (i & 3)
 *          j = Nb * Nr - (floor(i / Nb) * Nb) + (i % Nb)
 *          DecW[i] = InvMixColumn(W[j])
 *
 *
 * Example:
 *
 * When trying to recover an encrypted disk from a snapshotted virtual machine
 * running Linux with a disk encrypted with LUKS, running this program on the
 * memory dump may return:
 *
 *     [0x1ed89840..0x1ed89930] Found AES-256 encryption key:
 *              9de47610440c60c16fedaa38ffcd65fce1c1ebc11c2fad3c23c00188963c920a
 *     [0x1ed89930..0x1ed89a20] Found AES-256 decryption key:
 *              9de47610440c60c16fedaa38ffcd65fce1c1ebc11c2fad3c23c00188963c920a
 *     [0x1ed89a40..0x1ed89b30] Found AES-256 encryption key:
 *              ba2cf2c4225590fda1e41e6cc3f638d278e039e6d403b29df0a2e649c9c0a395
 *     [0x1ed89b30..0x1ed89c20] Found AES-256 decryption key:
 *              ba2cf2c4225590fda1e41e6cc3f638d278e039e6d403b29df0a2e649c9c0a395
 *
 * With the encrypted disk partition detected by file as:
 *     LUKS encrypted file, ver 1 [aes, xts-plain64, sha256]
 *
 * Algorithm AES-XTS uses two keys for encryption
 * (cf. https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS), so both keys
 * are needed to recover the LUKS master key.
 * This allows adding a new slot to the LUKS header with these commands:
 *
 *     echo 'ba2cf2c4225590fda1e41e6cc3f638d278e039e6d403b29df0a2e649c9c0a395' \
 *          '9de47610440c60c16fedaa38ffcd65fce1c1ebc11c2fad3c23c00188963c920a' \
 *         | xxd -p -r > master_key.bin
 *     cryptsetup luksAddKey --master-key-file=master_key.bin /dev/part.crypt
 */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Suppose that the round keys are aligned on 32-bit boundary */
#define ROUND_KEYS_ALIGNED_32BITS 1

/* Define 32-bit swap operation */
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
/* Windows SDK provides _byteswap_ulong in stdlib.h */
static uint32_t bswap_32(uint32_t x)
{
    return _byteswap_ulong(x);
}
#else
/* bswap_32 is defined in byteswap.h */
# include <byteswap.h>
#endif

/* Define 32-bit rotate-right operation */
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
/* Windows SDK provides _rotr in stdlib.h */
#elif defined(__i386__) || defined(__x86_64__)
/* Include x86 intrisics, if available */
# if defined(__GNUC__) || defined(__clang__)
#  include <x86intrin.h>
#  define USE_X86INTRIN_H 1
# endif
/* gcc provides _rotr in x86intrin.h, but not clang until version 9.0.0 */
# if defined(__GNUC__) && !(defined(__clang__) && __clang_major__ < 9)
# else
/* Use assembler */
static uint32_t _rotr(uint32_t x, int n)
{
    __asm__ __volatile__("rorl %2, %0" : "=r"(x) : "0"(x), "c"((int8_t)(n & 31)));
    return x;
}
# endif
#else
/* Default implementation */
static uint32_t _rotr(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}
#endif

static uint32_t rotr32(uint32_t x, int n)
{
    return _rotr(x, n);
}

/* AES key expansion algorithm, Round Constant */
static const uint32_t AES_RCON[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
};

static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static const uint32_t TE0_BIG[256] = {
    0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
    0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
    0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
    0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
    0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
    0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
    0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
    0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
    0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
    0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
    0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
    0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
    0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
    0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
    0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
    0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
    0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
    0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
    0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
    0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
    0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
    0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
    0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
    0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
    0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
    0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
    0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
    0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
    0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
    0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
    0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
    0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a,
};

static uint8_t extract_byte(uint32_t x, unsigned int n)
{
    return (uint8_t)(x >> (8 * n));
}

/* Compute SubWord(RotWord(word)) */
static uint32_t SubWord_RotWord(uint32_t word)
{
#if 0 && defined(USE_X86INTRIN_H)
    /* Use Intel AES-NI (Advanced Encryption Standard New Instructions)
     * ... or not, as it appears to slow things down
     */
    __m128i xmm_result;
    uint32_t xmm_content[4] = { 0, 0, 0, 0 };

    (void)AES_SBOX; /* Use the variable */
    xmm_content[1] = bswap_32(word);
    xmm_result = _mm_loadu_si128((void *)xmm_content);
    xmm_result = _mm_aeskeygenassist_si128(xmm_result, 0);
    xmm_result = _mm_bsrli_si128(xmm_result, 4);
    return bswap_32(_mm_cvtsi128_si32(xmm_result));
#else
    return (uint32_t)((AES_SBOX[extract_byte(word, 2)] << 24) |
                      (AES_SBOX[extract_byte(word, 1)] << 16) |
                      (AES_SBOX[extract_byte(word, 0)] << 8) |
                      AES_SBOX[extract_byte(word, 3)]);
#endif
}

/* Compute MixColumn
 * Use TE(InvSubBytes(word)) with TE(x) = MixColumn(SubBytes(x))
 *
 * MixColumn is faster than InvMixColumn (as this requires more operations),
 * but InvMixColumn is implemented in AES-NI.
 */
static uint32_t slow_MixColumn(uint32_t word)
{
    return TE0_BIG[AES_INV_SBOX[extract_byte(word, 3)]] ^
        rotr32(TE0_BIG[AES_INV_SBOX[extract_byte(word, 2)]], 8) ^
        rotr32(TE0_BIG[AES_INV_SBOX[extract_byte(word, 1)]], 16) ^
        rotr32(TE0_BIG[AES_INV_SBOX[extract_byte(word, 0)]], 24);
}

/* Fast implementation of MixColumn
 * The word is considered as a polynom in GF(2^8)[X] which is multiplied by
 * {03}X^3 + {01}X^2 + {01}X + {02} modulo X^4+1.
 */
static uint32_t MixColumn(uint32_t word)
{
    uint32_t word_02, word_03;

    word_02 = ((word & 0x7f7f7f7f) << 1) ^ (((word & 0x80808080) >> 7) * 0x1b);
    word_03 = word_02 ^ word;
    return word_02 ^ rotr32(word, 8) ^ rotr32(word, 16) ^ rotr32(word_03, 24);
}

#ifdef USE_X86INTRIN_H
/* Use AES-NI InvMixColumn transformation, which is slower than MixColumn */
static uint32_t x86_InvMixColumn(uint32_t word)
{
    __m128i xmm_result;
    uint32_t xmm_content[4] = { 0, 0, 0, 0 };

    xmm_content[0] = bswap_32(word);
    xmm_result = _mm_loadu_si128((void *)xmm_content);
    xmm_result = _mm_aesimc_si128(xmm_result);
    return bswap_32(_mm_cvtsi128_si32(xmm_result));
}
#endif

/* Run some quick benchmarks */
#define instruction_barrier() __asm__ __volatile__ ("" : : : "memory")
static void benchmark_MixColumn(void)
{
#if 0
    clock_t start_clock;
    double slow_time, fast_time;
    unsigned int count;
    const unsigned int max_count = 1000000000;
    uint32_t fast_word = 0, slow_word = 0;

    start_clock = clock();
    instruction_barrier();
    for (count = 0; count < max_count; count++) {
        fast_word = MixColumn(fast_word ^ count);
    }
    instruction_barrier();
    fast_time = (double)(clock() - start_clock) / CLOCKS_PER_SEC;

    start_clock = clock();
    instruction_barrier();
    for (count = 0; count < max_count; count++) {
        slow_word = slow_MixColumn(slow_word ^ count);
    }
    instruction_barrier();
    slow_time = (double)(clock() - start_clock) / CLOCKS_PER_SEC;

    if (fast_word != slow_word) {
        fprintf(stderr, "Incompatible implementations of MixColumn!\n");
        abort();
    }
    printf("MixColumn benchmark: %u operations in %.2fs (fast) and %.2fs (slow)\n",
           max_count, fast_time, slow_time);

# ifdef USE_X86INTRIN_H
    {
        uint32_t word, rev_word;
        double x86_time;

        /* Sanity check */
        for (count = 0; count < 256; count++) {
            word = MixColumn(count);
            rev_word = x86_InvMixColumn(word);
            assert(rev_word == count);
        }
        /* AES-NI benchmark */
        word = 0;
        start_clock = clock();
        instruction_barrier();
        for (count = 0; count < max_count; count++) {
            word = x86_InvMixColumn(word ^ count);
        }
        instruction_barrier();
        x86_time = (double)(clock() - start_clock) / CLOCKS_PER_SEC;
        printf("AES-NI InvMixColumn benchmark: %u operations in %.2fs (final word %#x)\n",
               max_count, x86_time, word);
    }
# endif
#endif
}

/* Reverse the bytes of a 32-bit integer */
static uint32_t reverse_u32(bool reversed, uint32_t word)
{
    return reversed ? bswap_32(word) : word;
}

static bool aes128_detect_enc(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    /* AES128: Nk = 4, Nr = 10 */
    const uint32_t *orig_ctx = ctx;
    unsigned int i;
    uint32_t tmp_w[8];

    tmp_w[0] = reverse_u32(!reversed, ctx[0]);
    tmp_w[1] = reverse_u32(!reversed, ctx[1]);
    tmp_w[2] = reverse_u32(!reversed, ctx[2]);
    tmp_w[3] = reverse_u32(!reversed, ctx[3]);

    for (i = 0; i < 10; i++) {
        ctx += 4;
        tmp_w[4] = tmp_w[0] ^ SubWord_RotWord(tmp_w[3]) ^ AES_RCON[i];
        if (tmp_w[4] != reverse_u32(!reversed, ctx[0]))
            return false;

        tmp_w[5] = tmp_w[1] ^ tmp_w[4];
        if (tmp_w[5] != reverse_u32(!reversed, ctx[1]))
            return false;

        tmp_w[6] = tmp_w[2] ^ tmp_w[5];
        if (tmp_w[6] != reverse_u32(!reversed, ctx[2]))
            return false;

        tmp_w[7] = tmp_w[3] ^ tmp_w[6];
        if (tmp_w[7] != reverse_u32(!reversed, ctx[3]))
            return false;

        tmp_w[0] = tmp_w[4];
        tmp_w[1] = tmp_w[5];
        tmp_w[2] = tmp_w[6];
        tmp_w[3] = tmp_w[7];
    }

    /* Found a key */
    key32[0] = reverse_u32(reversed, orig_ctx[0]);
    key32[1] = reverse_u32(reversed, orig_ctx[1]);
    key32[2] = reverse_u32(reversed, orig_ctx[2]);
    key32[3] = reverse_u32(reversed, orig_ctx[3]);
    return true;
}

static bool aes192_detect_enc(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    /* AES192: Nk = 6, Nr = 12 */
    const uint32_t *orig_ctx = ctx;
    unsigned int k, i = 0;
    uint32_t tmp_w[12];

    for (k = 0; k < 6; k++) {
        tmp_w[k] = reverse_u32(!reversed, ctx[k]);
    }

    for (;;) {
        ctx += 6;

        tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[i];
        if (tmp_w[6] != reverse_u32(!reversed, ctx[0]))
            return false;

        tmp_w[7] = tmp_w[1] ^ tmp_w[6];
        if (tmp_w[7] != reverse_u32(!reversed, ctx[1]))
            return false;

        tmp_w[8] = tmp_w[2] ^ tmp_w[7];
        if (tmp_w[8] != reverse_u32(!reversed, ctx[2]))
            return false;

        tmp_w[9] = tmp_w[3] ^ tmp_w[8];
        if (tmp_w[9] != reverse_u32(!reversed, ctx[3]))
            return false;

        if (++i == 8)
            break;

        tmp_w[10] = tmp_w[4] ^ tmp_w[9];
        if (tmp_w[10] != reverse_u32(!reversed, ctx[4]))
            return false;

        tmp_w[11] = tmp_w[5] ^ tmp_w[10];
        if (tmp_w[11] != reverse_u32(!reversed, ctx[5]))
            return false;

        for (k = 0; k < 6; k++) {
            tmp_w[k] = tmp_w[6 + k];
        }
    }

    for (k = 0; k < 6; k++) {
        key32[k] = reverse_u32(reversed, orig_ctx[k]);
    }
    return true;
}

static bool aes256_detect_enc(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    /* AES256: Nk = 8, Nr = 14 */
    const uint32_t *orig_ctx = ctx;
    unsigned int k, i = 0;
    uint32_t tmp_w[16];

    for (k = 0; k < 8; k++) {
        tmp_w[k] = reverse_u32(!reversed, ctx[k]);
    }

    for (;;) {
        ctx += 8;

        tmp_w[8] = tmp_w[0] ^ SubWord_RotWord(tmp_w[7]) ^ AES_RCON[i];
        if (tmp_w[8] != reverse_u32(!reversed, ctx[0]))
            return false;

        tmp_w[9] = tmp_w[1] ^ tmp_w[8];
        if (tmp_w[9] != reverse_u32(!reversed, ctx[1]))
            return false;

        tmp_w[10] = tmp_w[2] ^ tmp_w[9];
        if (tmp_w[10] != reverse_u32(!reversed, ctx[2]))
            return false;

        tmp_w[11] = tmp_w[3] ^ tmp_w[10];
        if (tmp_w[11] != reverse_u32(!reversed, ctx[3]))
            return false;

        if (++i == 7)
            break;

        tmp_w[12] = tmp_w[4] ^ SubWord_RotWord(rotr32(tmp_w[11], 8));
        if (tmp_w[12] != reverse_u32(!reversed, ctx[4]))
            return false;

        tmp_w[13] = tmp_w[5] ^ tmp_w[12];
        if (tmp_w[13] != reverse_u32(!reversed, ctx[5]))
            return false;

        tmp_w[14] = tmp_w[6] ^ tmp_w[13];
        if (tmp_w[14] != reverse_u32(!reversed, ctx[6]))
            return false;

        tmp_w[15] = tmp_w[7] ^ tmp_w[14];
        if (tmp_w[15] != reverse_u32(!reversed, ctx[7]))
            return false;

        for (k = 0; k < 8; k++) {
            tmp_w[k] = tmp_w[8 + k];
        }
    }

    for (k = 0; k < 8; k++) {
        key32[k] = reverse_u32(reversed, orig_ctx[k]);
    }
    return true;
}

static unsigned int aes_detect_enc(const uint32_t *ctx, void *key)
{
    if (aes128_detect_enc(true, ctx, key) || aes128_detect_enc(false, ctx, key))
        return 16;
    if (aes192_detect_enc(true, ctx, key) || aes192_detect_enc(false, ctx, key))
        return 24;
    if (aes256_detect_enc(true, ctx, key) || aes256_detect_enc(false, ctx, key))
        return 32;
    return 0;
}

/* Detect decryption values in Forward way */
static bool aes128_detect_decF(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    const uint32_t *orig_ctx = ctx;
    unsigned int i;
    uint32_t tmp_w[8];

    tmp_w[0] = reverse_u32(!reversed, ctx[0]);
    tmp_w[1] = reverse_u32(!reversed, ctx[1]);
    tmp_w[2] = reverse_u32(!reversed, ctx[2]);
    tmp_w[3] = reverse_u32(!reversed, ctx[3]);

    for (i = 0; i < 9; i++) {
        ctx += 4;
        tmp_w[4] = tmp_w[0] ^ SubWord_RotWord(tmp_w[3]) ^ AES_RCON[i];
        if (tmp_w[4] != MixColumn(reverse_u32(!reversed, ctx[0])))
            return false;

        tmp_w[5] = tmp_w[1] ^ tmp_w[4];
        if (tmp_w[5] != MixColumn(reverse_u32(!reversed, ctx[1])))
            return false;

        tmp_w[6] = tmp_w[2] ^ tmp_w[5];
        if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[2])))
            return false;

        tmp_w[7] = tmp_w[3] ^ tmp_w[6];
        if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[3])))
            return false;

        tmp_w[0] = tmp_w[4];
        tmp_w[1] = tmp_w[5];
        tmp_w[2] = tmp_w[6];
        tmp_w[3] = tmp_w[7];
    }
    ctx += 4;

    tmp_w[4] = tmp_w[0] ^ SubWord_RotWord(tmp_w[3]) ^ AES_RCON[9];
    if (tmp_w[4] != reverse_u32(!reversed, ctx[0]))
        return false;

    tmp_w[5] = tmp_w[1] ^ tmp_w[4];
    if (tmp_w[5] != reverse_u32(!reversed, ctx[1]))
        return false;

    tmp_w[6] = tmp_w[2] ^ tmp_w[5];
    if (tmp_w[6] != reverse_u32(!reversed, ctx[2]))
        return false;

    tmp_w[7] = tmp_w[3] ^ tmp_w[6];
    if (tmp_w[7] != reverse_u32(!reversed, ctx[3]))
        return false;

    key32[0] = reverse_u32(reversed, orig_ctx[0]);
    key32[1] = reverse_u32(reversed, orig_ctx[1]);
    key32[2] = reverse_u32(reversed, orig_ctx[2]);
    key32[3] = reverse_u32(reversed, orig_ctx[3]);
    return true;
}

/* Detect decryption values in Backward way */
static bool aes128_detect_decB(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    uint32_t tmp_w[8];
    unsigned int i;

    tmp_w[0] = reverse_u32(!reversed, ctx[40]);
    tmp_w[1] = reverse_u32(!reversed, ctx[41]);
    tmp_w[2] = reverse_u32(!reversed, ctx[42]);
    tmp_w[3] = reverse_u32(!reversed, ctx[43]);

    for (i = 0; i < 9; i++) {
        tmp_w[4] = tmp_w[0] ^ SubWord_RotWord(tmp_w[3]) ^ AES_RCON[i];
        if (tmp_w[4] != MixColumn(reverse_u32(!reversed, ctx[36 - 4 * i])))
            return false;

        tmp_w[5] = tmp_w[1] ^ tmp_w[4];
        if (tmp_w[5] != MixColumn(reverse_u32(!reversed, ctx[37 - 4 * i])))
            return false;

        tmp_w[6] = tmp_w[2] ^ tmp_w[5];
        if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[38 - 4 * i])))
            return false;

        tmp_w[7] = tmp_w[3] ^ tmp_w[6];
        if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[39 - 4 * i])))
            return false;

        tmp_w[0] = tmp_w[4];
        tmp_w[1] = tmp_w[5];
        tmp_w[2] = tmp_w[6];
        tmp_w[3] = tmp_w[7];
    }

    tmp_w[4] = tmp_w[0] ^ SubWord_RotWord(tmp_w[3]) ^ AES_RCON[9];
    if (tmp_w[4] != reverse_u32(!reversed, ctx[0]))
        return false;

    tmp_w[5] = tmp_w[1] ^ tmp_w[4];
    if (tmp_w[5] != reverse_u32(!reversed, ctx[1]))
        return false;

    tmp_w[6] = tmp_w[2] ^ tmp_w[5];
    if (tmp_w[6] != reverse_u32(!reversed, ctx[2]))
        return false;

    tmp_w[7] = tmp_w[3] ^ tmp_w[6];
    if (tmp_w[7] != reverse_u32(!reversed, ctx[3]))
        return false;

    key32[0] = reverse_u32(reversed, ctx[40]);
    key32[1] = reverse_u32(reversed, ctx[41]);
    key32[2] = reverse_u32(reversed, ctx[42]);
    key32[3] = reverse_u32(reversed, ctx[43]);
    return true;
}

static bool aes192_detect_decF(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    const uint32_t *orig_ctx = ctx;
    unsigned int i, k;
    uint32_t tmp_w[12];

    tmp_w[0] = reverse_u32(!reversed, ctx[0]);
    tmp_w[1] = reverse_u32(!reversed, ctx[1]);
    tmp_w[2] = reverse_u32(!reversed, ctx[2]);
    tmp_w[3] = reverse_u32(!reversed, ctx[3]);
    tmp_w[4] = MixColumn(reverse_u32(!reversed, ctx[4]));
    tmp_w[5] = MixColumn(reverse_u32(!reversed, ctx[5]));

    for (i = 0; i < 7; i++) {
        ctx += 6;
        tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[i];
        if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[0])))
            return false;

        tmp_w[7] = tmp_w[1] ^ tmp_w[6];
        if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[1])))
            return false;

        tmp_w[8] = tmp_w[2] ^ tmp_w[7];
        if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[2])))
            return false;

        tmp_w[9] = tmp_w[3] ^ tmp_w[8];
        if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[3])))
            return false;

        tmp_w[10] = tmp_w[4] ^ tmp_w[9];
        if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[4])))
            return false;

        tmp_w[11] = tmp_w[5] ^ tmp_w[10];
        if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[5])))
            return false;

        for (k = 0; k < 6; k++) {
            tmp_w[k] = tmp_w[6 + k];
        }
    }
    ctx += 6;

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[7];
    if (tmp_w[6] != reverse_u32(!reversed, ctx[0]))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != reverse_u32(!reversed, ctx[1]))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != reverse_u32(!reversed, ctx[2]))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != reverse_u32(!reversed, ctx[3]))
        return false;

    key32[0] = reverse_u32(reversed, orig_ctx[0]);
    key32[1] = reverse_u32(reversed, orig_ctx[1]);
    key32[2] = reverse_u32(reversed, orig_ctx[2]);
    key32[3] = reverse_u32(reversed, orig_ctx[3]);
    key32[4] = bswap_32(MixColumn(reverse_u32(!reversed, orig_ctx[4])));
    key32[5] = bswap_32(MixColumn(reverse_u32(!reversed, orig_ctx[5])));
    return true;
}

static bool aes192_detect_decB(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    uint32_t tmp_w[12];
    unsigned int k;

    tmp_w[0] = reverse_u32(!reversed, ctx[48]);
    tmp_w[1] = reverse_u32(!reversed, ctx[49]);
    tmp_w[2] = reverse_u32(!reversed, ctx[50]);
    tmp_w[3] = reverse_u32(!reversed, ctx[51]);
    tmp_w[4] = MixColumn(reverse_u32(!reversed, ctx[44]));
    tmp_w[5] = MixColumn(reverse_u32(!reversed, ctx[45]));

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[0];
    if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[46])))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[47])))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[40])))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[41])))
        return false;

    tmp_w[10] = tmp_w[4] ^ tmp_w[9];
    if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[42])))
        return false;

    tmp_w[11] = tmp_w[5] ^ tmp_w[10];
    if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[43])))
        return false;

    for (k = 0; k < 6; k++) {
        tmp_w[k] = tmp_w[6 + k];
    }

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[1];
    if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[36])))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[37])))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[38])))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[39])))
        return false;

    tmp_w[10] = tmp_w[4] ^ tmp_w[9];
    if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[32])))
        return false;

    tmp_w[11] = tmp_w[5] ^ tmp_w[10];
    if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[33])))
        return false;

    for (k = 0; k < 6; k++) {
        tmp_w[k] = tmp_w[6 + k];
    }

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[2];
    if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[34])))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[35])))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[28])))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[29])))
        return false;

    tmp_w[10] = tmp_w[4] ^ tmp_w[9];
    if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[30])))
        return false;

    tmp_w[11] = tmp_w[5] ^ tmp_w[10];
    if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[31])))
        return false;

    for (k = 0; k < 6; k++) {
        tmp_w[k] = tmp_w[6 + k];
    }

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[3];
    if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[24])))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[25])))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[26])))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[27])))
        return false;

    tmp_w[10] = tmp_w[4] ^ tmp_w[9];
    if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[20])))
        return false;

    tmp_w[11] = tmp_w[5] ^ tmp_w[10];
    if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[21])))
        return false;

    for (k = 0; k < 6; k++) {
        tmp_w[k] = tmp_w[6 + k];
    }

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[4];
    if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[22])))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[23])))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[16])))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[17])))
        return false;

    tmp_w[10] = tmp_w[4] ^ tmp_w[9];
    if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[18])))
        return false;

    tmp_w[11] = tmp_w[5] ^ tmp_w[10];
    if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[19])))
        return false;

    for (k = 0; k < 6; k++) {
        tmp_w[k] = tmp_w[6 + k];
    }

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[5];
    if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[12])))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[13])))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[14])))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[15])))
        return false;

    tmp_w[10] = tmp_w[4] ^ tmp_w[9];
    if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[8])))
        return false;

    tmp_w[11] = tmp_w[5] ^ tmp_w[10];
    if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[9])))
        return false;

    for (k = 0; k < 6; k++) {
        tmp_w[k] = tmp_w[6 + k];
    }

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[6];
    if (tmp_w[6] != MixColumn(reverse_u32(!reversed, ctx[10])))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != MixColumn(reverse_u32(!reversed, ctx[11])))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[4])))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[5])))
        return false;

    tmp_w[10] = tmp_w[4] ^ tmp_w[9];
    if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[6])))
        return false;

    tmp_w[11] = tmp_w[5] ^ tmp_w[10];
    if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[7])))
        return false;

    for (k = 0; k < 6; k++) {
        tmp_w[k] = tmp_w[6 + k];
    }

    tmp_w[6] = tmp_w[0] ^ SubWord_RotWord(tmp_w[5]) ^ AES_RCON[7];
    if (tmp_w[6] != reverse_u32(!reversed, ctx[0]))
        return false;

    tmp_w[7] = tmp_w[1] ^ tmp_w[6];
    if (tmp_w[7] != reverse_u32(!reversed, ctx[1]))
        return false;

    tmp_w[8] = tmp_w[2] ^ tmp_w[7];
    if (tmp_w[8] != reverse_u32(!reversed, ctx[2]))
        return false;

    tmp_w[9] = tmp_w[3] ^ tmp_w[8];
    if (tmp_w[9] != reverse_u32(!reversed, ctx[3]))
        return false;

    key32[0] = reverse_u32(reversed, ctx[48]);
    key32[1] = reverse_u32(reversed, ctx[49]);
    key32[2] = reverse_u32(reversed, ctx[50]);
    key32[3] = reverse_u32(reversed, ctx[51]);
    key32[4] = bswap_32(MixColumn(reverse_u32(!reversed, ctx[44])));
    key32[5] = bswap_32(MixColumn(reverse_u32(!reversed, ctx[45])));
    return true;
}

static bool aes256_detect_decF(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    const uint32_t *orig_ctx = ctx;
    unsigned int i, k;
    uint32_t tmp_w[16];

    tmp_w[0] = reverse_u32(!reversed, ctx[0]);
    tmp_w[1] = reverse_u32(!reversed, ctx[1]);
    tmp_w[2] = reverse_u32(!reversed, ctx[2]);
    tmp_w[3] = reverse_u32(!reversed, ctx[3]);
    tmp_w[4] = MixColumn(reverse_u32(!reversed, ctx[4]));
    tmp_w[5] = MixColumn(reverse_u32(!reversed, ctx[5]));
    tmp_w[6] = MixColumn(reverse_u32(!reversed, ctx[6]));
    tmp_w[7] = MixColumn(reverse_u32(!reversed, ctx[7]));

    for (i = 0; i < 6; i++) {
        ctx += 8;
        tmp_w[8] = tmp_w[0] ^ SubWord_RotWord(tmp_w[7]) ^ AES_RCON[i];
        if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[0])))
            return false;

        tmp_w[9] = tmp_w[1] ^ tmp_w[8];
        if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[1])))
            return false;

        tmp_w[10] = tmp_w[2] ^ tmp_w[9];
        if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[2])))
            return false;

        tmp_w[11] = tmp_w[3] ^ tmp_w[10];
        if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[3])))
            return false;

        tmp_w[12] = tmp_w[4] ^ SubWord_RotWord(rotr32(tmp_w[11], 8));
        if (tmp_w[12] != MixColumn(reverse_u32(!reversed, ctx[4])))
            return false;

        tmp_w[13] = tmp_w[5] ^ tmp_w[12];
        if (tmp_w[13] != MixColumn(reverse_u32(!reversed, ctx[5])))
            return false;

        tmp_w[14] = tmp_w[6] ^ tmp_w[13];
        if (tmp_w[14] != MixColumn(reverse_u32(!reversed, ctx[6])))
            return false;

        tmp_w[15] = tmp_w[7] ^ tmp_w[14];
        if (tmp_w[15] != MixColumn(reverse_u32(!reversed, ctx[7])))
            return false;

        for (k = 0; k < 8; k++) {
            tmp_w[k] = tmp_w[8 + k];
        }
    }
    ctx += 8;

    tmp_w[8] = tmp_w[0] ^ SubWord_RotWord(tmp_w[7]) ^ AES_RCON[6];
    if (tmp_w[8] != reverse_u32(!reversed, ctx[0]))
        return false;

    tmp_w[9] = tmp_w[1] ^ tmp_w[8];
    if (tmp_w[9] != reverse_u32(!reversed, ctx[1]))
        return false;

    tmp_w[10] = tmp_w[2] ^ tmp_w[9];
    if (tmp_w[10] != reverse_u32(!reversed, ctx[2]))
        return false;

    tmp_w[11] = tmp_w[3] ^ tmp_w[10];
    if (tmp_w[11] != reverse_u32(!reversed, ctx[3]))
        return false;

    key32[0] = reverse_u32(reversed, orig_ctx[0]);
    key32[1] = reverse_u32(reversed, orig_ctx[1]);
    key32[2] = reverse_u32(reversed, orig_ctx[2]);
    key32[3] = reverse_u32(reversed, orig_ctx[3]);
    key32[4] = bswap_32(MixColumn(reverse_u32(!reversed, orig_ctx[4])));
    key32[5] = bswap_32(MixColumn(reverse_u32(!reversed, orig_ctx[5])));
    key32[6] = bswap_32(MixColumn(reverse_u32(!reversed, orig_ctx[6])));
    key32[7] = bswap_32(MixColumn(reverse_u32(!reversed, orig_ctx[7])));
    return true;
}

static bool aes256_detect_decB(bool reversed, const uint32_t *ctx, uint32_t *key32)
{
    uint32_t tmp_w[16];
    unsigned int i, k;

    tmp_w[0] = reverse_u32(!reversed, ctx[56]);
    tmp_w[1] = reverse_u32(!reversed, ctx[57]);
    tmp_w[2] = reverse_u32(!reversed, ctx[58]);
    tmp_w[3] = reverse_u32(!reversed, ctx[59]);
    tmp_w[4] = MixColumn(reverse_u32(!reversed, ctx[52]));
    tmp_w[5] = MixColumn(reverse_u32(!reversed, ctx[53]));
    tmp_w[6] = MixColumn(reverse_u32(!reversed, ctx[54]));
    tmp_w[7] = MixColumn(reverse_u32(!reversed, ctx[55]));

    for (i = 0; i < 6; i++) {
        tmp_w[8] = tmp_w[0] ^ SubWord_RotWord(tmp_w[7]) ^ AES_RCON[i];
        if (tmp_w[8] != MixColumn(reverse_u32(!reversed, ctx[48 - 8 * i])))
            return false;

        tmp_w[9] = tmp_w[1] ^ tmp_w[8];
        if (tmp_w[9] != MixColumn(reverse_u32(!reversed, ctx[49 - 8 * i])))
            return false;

        tmp_w[10] = tmp_w[2] ^ tmp_w[9];
        if (tmp_w[10] != MixColumn(reverse_u32(!reversed, ctx[50 - 8 * i])))
            return false;

        tmp_w[11] = tmp_w[3] ^ tmp_w[10];
        if (tmp_w[11] != MixColumn(reverse_u32(!reversed, ctx[51 - 8 * i])))
            return false;

        tmp_w[12] = tmp_w[4] ^ SubWord_RotWord(rotr32(tmp_w[11], 8));
        if (tmp_w[12] != MixColumn(reverse_u32(!reversed, ctx[44 - 8 * i])))
            return false;

        tmp_w[13] = tmp_w[5] ^ tmp_w[12];
        if (tmp_w[13] != MixColumn(reverse_u32(!reversed, ctx[45 - 8 * i])))
            return false;

        tmp_w[14] = tmp_w[6] ^ tmp_w[13];
        if (tmp_w[14] != MixColumn(reverse_u32(!reversed, ctx[46 - 8 * i])))
            return false;

        tmp_w[15] = tmp_w[7] ^ tmp_w[14];
        if (tmp_w[15] != MixColumn(reverse_u32(!reversed, ctx[47 - 8 * i])))
            return false;

        for (k = 0; k < 8; k++) {
            tmp_w[k] = tmp_w[8 + k];
        }
    }

    tmp_w[8] = tmp_w[0] ^ SubWord_RotWord(tmp_w[7]) ^ AES_RCON[6];
    if (tmp_w[8] != reverse_u32(!reversed, ctx[0]))
        return false;

    tmp_w[9] = tmp_w[1] ^ tmp_w[8];
    if (tmp_w[9] != reverse_u32(!reversed, ctx[1]))
        return false;

    tmp_w[10] = tmp_w[2] ^ tmp_w[9];
    if (tmp_w[10] != reverse_u32(!reversed, ctx[2]))
        return false;

    tmp_w[11] = tmp_w[3] ^ tmp_w[10];
    if (tmp_w[11] != reverse_u32(!reversed, ctx[3]))
        return false;

    key32[0] = reverse_u32(reversed, ctx[56]);
    key32[1] = reverse_u32(reversed, ctx[57]);
    key32[2] = reverse_u32(reversed, ctx[58]);
    key32[3] = reverse_u32(reversed, ctx[59]);
    key32[4] = bswap_32(MixColumn(reverse_u32(!reversed, ctx[52])));
    key32[5] = bswap_32(MixColumn(reverse_u32(!reversed, ctx[53])));
    key32[6] = bswap_32(MixColumn(reverse_u32(!reversed, ctx[54])));
    key32[7] = bswap_32(MixColumn(reverse_u32(!reversed, ctx[55])));
    return true;
}

static unsigned int aes_detect_dec_with_rev(bool reversed, const uint32_t *ctx, void *key)
{
    if (aes128_detect_decF(reversed, ctx, key) || aes128_detect_decB(reversed, ctx, key))
        return 16;
    if (aes192_detect_decF(reversed, ctx, key) || aes192_detect_decB(reversed, ctx, key))
        return 24;
    if (aes256_detect_decF(reversed, ctx, key) || aes256_detect_decB(reversed, ctx, key))
        return 32;
    return 0;
}

static unsigned int aes_detect_dec(const uint32_t *ctx, void *key)
{
    unsigned int len;

    len = aes_detect_dec_with_rev(true, ctx, key);
    if (len)
        return len;
    return aes_detect_dec_with_rev(false, ctx, key);
}

static void self_test(void)
{
    /* Test states of key 01020304... */
    static const uint32_t aes128_encB[] = {
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
        0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe,
        0xb692cf0b, 0x643dbdf1, 0xbe9bc500, 0x6830b3fe,
        0xb6ff744e, 0xd2c2c9bf, 0x6c590cbf, 0x0469bf41,
        0x47f7f7bc, 0x95353e03, 0xf96c32bc, 0xfd058dfd,
        0x3caaa3e8, 0xa99f9deb, 0x50f3af57, 0xadf622aa,
        0x5e390f7d, 0xf7a69296, 0xa7553dc1, 0x0aa31f6b,
        0x14f9701a, 0xe35fe28c, 0x440adf4d, 0x4ea9c026,
        0x47438735, 0xa41c65b9, 0xe016baf4, 0xaebf7ad2,
        0x549932d1, 0xf0855768, 0x1093ed9c, 0xbe2c974e,
        0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5,
    };
    static const uint32_t aes128_encL[] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0xfd74aad6, 0xfa72afd2, 0xf178a6da, 0xfe76abd6,
        0x0bcf92b6, 0xf1bd3d64, 0x00c59bbe, 0xfeb33068,
        0x4e74ffb6, 0xbfc9c2d2, 0xbf0c596c, 0x41bf6904,
        0xbcf7f747, 0x033e3595, 0xbc326cf9, 0xfd8d05fd,
        0xe8a3aa3c, 0xeb9d9fa9, 0x57aff350, 0xaa22f6ad,
        0x7d0f395e, 0x9692a6f7, 0xc13d55a7, 0x6b1fa30a,
        0x1a70f914, 0x8ce25fe3, 0x4ddf0a44, 0x26c0a94e,
        0x35874347, 0xb9651ca4, 0xf4ba16e0, 0xd27abfae,
        0xd1329954, 0x685785f0, 0x9ced9310, 0x4e972cbe,
        0x7f1d1113, 0x174a94e3, 0x8ba707f3, 0xc5302b4d,
    };
    static const uint32_t aes192_encB[] = {
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
        0x10111213, 0x14151617, 0x5846f2f9, 0x5c43f4fe,
        0x544afef5, 0x5847f0fa, 0x4856e2e9, 0x5c43f4fe,
        0x40f949b3, 0x1cbabd4d, 0x48f043b8, 0x10b7b342,
        0x58e151ab, 0x04a2a555, 0x7effb541, 0x6245080c,
        0x2ab54bb4, 0x3a02f8f6, 0x62e3a95d, 0x66410c08,
        0xf5018572, 0x97448d7e, 0xbdf1c6ca, 0x87f33e3c,
        0xe5109761, 0x83519b69, 0x34157c9e, 0xa351f1e0,
        0x1ea0372a, 0x99530916, 0x7c439e77, 0xff12051e,
        0xdd7e0e88, 0x7e2fff68, 0x608fc842, 0xf9dcc154,
        0x859f5f23, 0x7a8d5a3d, 0xc0c02952, 0xbeefd63a,
        0xde601e78, 0x27bcdf2c, 0xa223800f, 0xd8aeda32,
        0xa4970a33, 0x1a78dc09, 0xc418c271, 0xe3a41d5d,
    };
    static const uint32_t aes192_encL[] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0xf9f24658, 0xfef4435c,
        0xf5fe4a54, 0xfaf04758, 0xe9e25648, 0xfef4435c,
        0xb349f940, 0x4dbdba1c, 0xb843f048, 0x42b3b710,
        0xab51e158, 0x55a5a204, 0x41b5ff7e, 0x0c084562,
        0xb44bb52a, 0xf6f8023a, 0x5da9e362, 0x080c4166,
        0x728501f5, 0x7e8d4497, 0xcac6f1bd, 0x3c3ef387,
        0x619710e5, 0x699b5183, 0x9e7c1534, 0xe0f151a3,
        0x2a37a01e, 0x16095399, 0x779e437c, 0x1e0512ff,
        0x880e7edd, 0x68ff2f7e, 0x42c88f60, 0x54c1dcf9,
        0x235f9f85, 0x3d5a8d7a, 0x5229c0c0, 0x3ad6efbe,
        0x781e60de, 0x2cdfbc27, 0x0f8023a2, 0x32daaed8,
        0x330a97a4, 0x09dc781a, 0x71c218c4, 0x5d1da4e3,

    };
    static const uint32_t aes256_encB[] = {
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
        0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
        0xa573c29f, 0xa176c498, 0xa97fce93, 0xa572c09c,
        0x1651a8cd, 0x0244beda, 0x1a5da4c1, 0x0640bade,
        0xae87dff0, 0x0ff11b68, 0xa68ed5fb, 0x03fc1567,
        0x6de1f148, 0x6fa54f92, 0x75f8eb53, 0x73b8518d,
        0xc656827f, 0xc9a79917, 0x6f294cec, 0x6cd5598b,
        0x3de23a75, 0x524775e7, 0x27bf9eb4, 0x5407cf39,
        0x0bdc905f, 0xc27b0948, 0xad5245a4, 0xc1871c2f,
        0x45f5a660, 0x17b2d387, 0x300d4d33, 0x640a820a,
        0x7ccff71c, 0xbeb4fe54, 0x13e6bbf0, 0xd261a7df,
        0xf01afafe, 0xe7a82979, 0xd7a5644a, 0xb3afe640,
        0x2541fe71, 0x9bf50025, 0x8813bbd5, 0x5a721c0a,
        0x4e5a6699, 0xa9f24fe0, 0x7e572baa, 0xcdf8cdea,
        0x24fc79cc, 0xbf0979e9, 0x371ac23c, 0x6d68de36,
    };
    static const uint32_t aes256_encL[] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x9fc273a5, 0x98c476a1, 0x93ce7fa9, 0x9cc072a5,
        0xcda85116, 0xdabe4402, 0xc1a45d1a, 0xdeba4006,
        0xf0df87ae, 0x681bf10f, 0xfbd58ea6, 0x6715fc03,
        0x48f1e16d, 0x924fa56f, 0x53ebf875, 0x8d51b873,
        0x7f8256c6, 0x1799a7c9, 0xec4c296f, 0x8b59d56c,
        0x753ae23d, 0xe7754752, 0xb49ebf27, 0x39cf0754,
        0x5f90dc0b, 0x48097bc2, 0xa44552ad, 0x2f1c87c1,
        0x60a6f545, 0x87d3b217, 0x334d0d30, 0x0a820a64,
        0x1cf7cf7c, 0x54feb4be, 0xf0bbe613, 0xdfa761d2,
        0xfefa1af0, 0x7929a8e7, 0x4a64a5d7, 0x40e6afb3,
        0x71fe4125, 0x2500f59b, 0xd5bb1388, 0x0a1c725a,
        0x99665a4e, 0xe04ff2a9, 0xaa2b577e, 0xeacdf8cd,
        0xcc79fc24, 0xe97909bf, 0x3cc21a37, 0x36de686d,
    };

    static const uint32_t aes128_decBF[] = {
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
        0x8c56dff0, 0x825dd3f9, 0x805ad3fc, 0x8659d7fd,
        0xa0db0299, 0x2286d160, 0xa2dc029c, 0x2485d561,
        0xc7c6e391, 0xe54032f1, 0x479c306d, 0x6319e50c,
        0xa8a2f504, 0x4de2c7f5, 0x0a7ef798, 0x69671294,
        0x2ec41027, 0x6326d7d2, 0x6958204a, 0x003f32de,
        0x72e3098d, 0x11c5de5f, 0x789dfe15, 0x78a2cccb,
        0x8d82fc74, 0x9c47222b, 0xe4dadc3e, 0x9c7810f5,
        0x1362a463, 0x8f258648, 0x6bff5a76, 0xf7874a83,
        0x13aa29be, 0x9c8faff6, 0xf770f580, 0x00f7bf03,
        0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5,
    };
    static const uint32_t aes128_decBB[] = {
        0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5,
        0x13aa29be, 0x9c8faff6, 0xf770f580, 0x00f7bf03,
        0x1362a463, 0x8f258648, 0x6bff5a76, 0xf7874a83,
        0x8d82fc74, 0x9c47222b, 0xe4dadc3e, 0x9c7810f5,
        0x72e3098d, 0x11c5de5f, 0x789dfe15, 0x78a2cccb,
        0x2ec41027, 0x6326d7d2, 0x6958204a, 0x003f32de,
        0xa8a2f504, 0x4de2c7f5, 0x0a7ef798, 0x69671294,
        0xc7c6e391, 0xe54032f1, 0x479c306d, 0x6319e50c,
        0xa0db0299, 0x2286d160, 0xa2dc029c, 0x2485d561,
        0x8c56dff0, 0x825dd3f9, 0x805ad3fc, 0x8659d7fd,
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
    };
    static const uint32_t aes128_decLF[] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0xf0df568c, 0xf9d35d82, 0xfcd35a80, 0xfdd75986,
        0x9902dba0, 0x60d18622, 0x9c02dca2, 0x61d58524,
        0x91e3c6c7, 0xf13240e5, 0x6d309c47, 0x0ce51963,
        0x04f5a2a8, 0xf5c7e24d, 0x98f77e0a, 0x94126769,
        0x2710c42e, 0xd2d72663, 0x4a205869, 0xde323f00,
        0x8d09e372, 0x5fdec511, 0x15fe9d78, 0xcbcca278,
        0x74fc828d, 0x2b22479c, 0x3edcdae4, 0xf510789c,
        0x63a46213, 0x4886258f, 0x765aff6b, 0x834a87f7,
        0xbe29aa13, 0xf6af8f9c, 0x80f570f7, 0x03bff700,
        0x7f1d1113, 0x174a94e3, 0x8ba707f3, 0xc5302b4d,
    };
    static const uint32_t aes128_decLB[] = {
        0x7f1d1113, 0x174a94e3, 0x8ba707f3, 0xc5302b4d,
        0xbe29aa13, 0xf6af8f9c, 0x80f570f7, 0x03bff700,
        0x63a46213, 0x4886258f, 0x765aff6b, 0x834a87f7,
        0x74fc828d, 0x2b22479c, 0x3edcdae4, 0xf510789c,
        0x8d09e372, 0x5fdec511, 0x15fe9d78, 0xcbcca278,
        0x2710c42e, 0xd2d72663, 0x4a205869, 0xde323f00,
        0x04f5a2a8, 0xf5c7e24d, 0x98f77e0a, 0x94126769,
        0x91e3c6c7, 0xf13240e5, 0x6d309c47, 0x0ce51963,
        0x9902dba0, 0x60d18622, 0x9c02dca2, 0x61d58524,
        0xf0df568c, 0xf9d35d82, 0xfcd35a80, 0xfdd75986,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    };
    static const uint32_t aes192_decBF[] = {
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
        0x1a1f181d, 0x1e1b1c19, 0x4742c7d7, 0x4949cbde,
        0x4b4ecbdb, 0x4d4dcfda, 0x5752d7c7, 0x4949cbde,
        0x60dcef10, 0x299524ce, 0x62dbef15, 0x2f9620cf,
        0x78c4f708, 0x318d3cd6, 0x9655b701, 0xbfc093cf,
        0xdd1b7cda, 0xf28d5c15, 0x8a49ab1d, 0xbbc497cb,
        0xc6deb0ab, 0x791e2364, 0xa4055fbe, 0x568803ab,
        0xdcc1a8b6, 0x67053f7d, 0xcc5c194a, 0xb5423a2e,
        0x11476590, 0x47cf663b, 0x9b0ece8d, 0xfc0bf1f0,
        0xf77d6ec1, 0x423f54ef, 0x5378317f, 0x14b75744,
        0x8fb999c9, 0x73b26839, 0xc7f9d89d, 0x85c68c72,
        0xd6bebd0d, 0xc209ea49, 0x4db07380, 0x3e021bb9,
        0xa4970a33, 0x1a78dc09, 0xc418c271, 0xe3a41d5d,
    };
    static const uint32_t aes192_decBB[] = {
        0xa4970a33, 0x1a78dc09, 0xc418c271, 0xe3a41d5d,
        0xd6bebd0d, 0xc209ea49, 0x4db07380, 0x3e021bb9,
        0x8fb999c9, 0x73b26839, 0xc7f9d89d, 0x85c68c72,
        0xf77d6ec1, 0x423f54ef, 0x5378317f, 0x14b75744,
        0x11476590, 0x47cf663b, 0x9b0ece8d, 0xfc0bf1f0,
        0xdcc1a8b6, 0x67053f7d, 0xcc5c194a, 0xb5423a2e,
        0xc6deb0ab, 0x791e2364, 0xa4055fbe, 0x568803ab,
        0xdd1b7cda, 0xf28d5c15, 0x8a49ab1d, 0xbbc497cb,
        0x78c4f708, 0x318d3cd6, 0x9655b701, 0xbfc093cf,
        0x60dcef10, 0x299524ce, 0x62dbef15, 0x2f9620cf,
        0x4b4ecbdb, 0x4d4dcfda, 0x5752d7c7, 0x4949cbde,
        0x1a1f181d, 0x1e1b1c19, 0x4742c7d7, 0x4949cbde,
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
    };
    static const uint32_t aes192_decLF[] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x1d181f1a, 0x191c1b1e, 0xd7c74247, 0xdecb4949,
        0xdbcb4e4b, 0xdacf4d4d, 0xc7d75257, 0xdecb4949,
        0x10efdc60, 0xce249529, 0x15efdb62, 0xcf20962f,
        0x08f7c478, 0xd63c8d31, 0x01b75596, 0xcf93c0bf,
        0xda7c1bdd, 0x155c8df2, 0x1dab498a, 0xcb97c4bb,
        0xabb0dec6, 0x64231e79, 0xbe5f05a4, 0xab038856,
        0xb6a8c1dc, 0x7d3f0567, 0x4a195ccc, 0x2e3a42b5,
        0x90654711, 0x3b66cf47, 0x8dce0e9b, 0xf0f10bfc,
        0xc16e7df7, 0xef543f42, 0x7f317853, 0x4457b714,
        0xc999b98f, 0x3968b273, 0x9dd8f9c7, 0x728cc685,
        0x0dbdbed6, 0x49ea09c2, 0x8073b04d, 0xb91b023e,
        0x330a97a4, 0x09dc781a, 0x71c218c4, 0x5d1da4e3,
    };
    static const uint32_t aes192_decLB[] = {
        0x330a97a4, 0x09dc781a, 0x71c218c4, 0x5d1da4e3,
        0x0dbdbed6, 0x49ea09c2, 0x8073b04d, 0xb91b023e,
        0xc999b98f, 0x3968b273, 0x9dd8f9c7, 0x728cc685,
        0xc16e7df7, 0xef543f42, 0x7f317853, 0x4457b714,
        0x90654711, 0x3b66cf47, 0x8dce0e9b, 0xf0f10bfc,
        0xb6a8c1dc, 0x7d3f0567, 0x4a195ccc, 0x2e3a42b5,
        0xabb0dec6, 0x64231e79, 0xbe5f05a4, 0xab038856,
        0xda7c1bdd, 0x155c8df2, 0x1dab498a, 0xcb97c4bb,
        0x08f7c478, 0xd63c8d31, 0x01b75596, 0xcf93c0bf,
        0x10efdc60, 0xce249529, 0x15efdb62, 0xcf20962f,
        0xdbcb4e4b, 0xdacf4d4d, 0xc7d75257, 0xdecb4949,
        0x1d181f1a, 0x191c1b1e, 0xd7c74247, 0xdecb4949,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    };
    static const uint32_t aes256_decBF[] = {
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
        0x1a1f181d, 0x1e1b1c19, 0x12171015, 0x16131411,
        0x2a2840c9, 0x24234cc0, 0x26244cc5, 0x202748c4,
        0x7fd7850f, 0x61cc9916, 0x73db8903, 0x65c89d12,
        0x15c668bd, 0x31e5247d, 0x17c168b8, 0x37e6207c,
        0xaed55816, 0xcf19c100, 0xbcc24803, 0xd90ad511,
        0xde69409a, 0xef8c64e7, 0xf84d0c5f, 0xcfab2c23,
        0xf85fc4f3, 0x374605f3, 0x8b844df0, 0x528e98e1,
        0x3ca69715, 0xd32af3f2, 0x2b67ffad, 0xe4ccd38e,
        0x74da7ba3, 0x439c7e50, 0xc81833a0, 0x9a96ab41,
        0xb5708e13, 0x665a7de1, 0x4d3d824c, 0xa9f151c2,
        0xc8a30580, 0x8b3f7bd0, 0x43274870, 0xd9b1e331,
        0x5e1648eb, 0x384c350a, 0x7571b746, 0xdc80e684,
        0x34f1d1ff, 0xbfceaa2f, 0xfce9e25f, 0x2558016e,
        0x24fc79cc, 0xbf0979e9, 0x371ac23c, 0x6d68de36,
    };
    static const uint32_t aes256_decBB[] = {
        0x24fc79cc, 0xbf0979e9, 0x371ac23c, 0x6d68de36,
        0x34f1d1ff, 0xbfceaa2f, 0xfce9e25f, 0x2558016e,
        0x5e1648eb, 0x384c350a, 0x7571b746, 0xdc80e684,
        0xc8a30580, 0x8b3f7bd0, 0x43274870, 0xd9b1e331,
        0xb5708e13, 0x665a7de1, 0x4d3d824c, 0xa9f151c2,
        0x74da7ba3, 0x439c7e50, 0xc81833a0, 0x9a96ab41,
        0x3ca69715, 0xd32af3f2, 0x2b67ffad, 0xe4ccd38e,
        0xf85fc4f3, 0x374605f3, 0x8b844df0, 0x528e98e1,
        0xde69409a, 0xef8c64e7, 0xf84d0c5f, 0xcfab2c23,
        0xaed55816, 0xcf19c100, 0xbcc24803, 0xd90ad511,
        0x15c668bd, 0x31e5247d, 0x17c168b8, 0x37e6207c,
        0x7fd7850f, 0x61cc9916, 0x73db8903, 0x65c89d12,
        0x2a2840c9, 0x24234cc0, 0x26244cc5, 0x202748c4,
        0x1a1f181d, 0x1e1b1c19, 0x12171015, 0x16131411,
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
    };
    static const uint32_t aes256_decLF[] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x1d181f1a, 0x191c1b1e, 0x15101712, 0x11141316,
        0xc940282a, 0xc04c2324, 0xc54c2426, 0xc4482720,
        0x0f85d77f, 0x1699cc61, 0x0389db73, 0x129dc865,
        0xbd68c615, 0x7d24e531, 0xb868c117, 0x7c20e637,
        0x1658d5ae, 0x00c119cf, 0x0348c2bc, 0x11d50ad9,
        0x9a4069de, 0xe7648cef, 0x5f0c4df8, 0x232cabcf,
        0xf3c45ff8, 0xf3054637, 0xf04d848b, 0xe1988e52,
        0x1597a63c, 0xf2f32ad3, 0xadff672b, 0x8ed3cce4,
        0xa37bda74, 0x507e9c43, 0xa03318c8, 0x41ab969a,
        0x138e70b5, 0xe17d5a66, 0x4c823d4d, 0xc251f1a9,
        0x8005a3c8, 0xd07b3f8b, 0x70482743, 0x31e3b1d9,
        0xeb48165e, 0x0a354c38, 0x46b77175, 0x84e680dc,
        0xffd1f134, 0x2faacebf, 0x5fe2e9fc, 0x6e015825,
        0xcc79fc24, 0xe97909bf, 0x3cc21a37, 0x36de686d,
    };
    static const uint32_t aes256_decLB[] = {
        0xcc79fc24, 0xe97909bf, 0x3cc21a37, 0x36de686d,
        0xffd1f134, 0x2faacebf, 0x5fe2e9fc, 0x6e015825,
        0xeb48165e, 0x0a354c38, 0x46b77175, 0x84e680dc,
        0x8005a3c8, 0xd07b3f8b, 0x70482743, 0x31e3b1d9,
        0x138e70b5, 0xe17d5a66, 0x4c823d4d, 0xc251f1a9,
        0xa37bda74, 0x507e9c43, 0xa03318c8, 0x41ab969a,
        0x1597a63c, 0xf2f32ad3, 0xadff672b, 0x8ed3cce4,
        0xf3c45ff8, 0xf3054637, 0xf04d848b, 0xe1988e52,
        0x9a4069de, 0xe7648cef, 0x5f0c4df8, 0x232cabcf,
        0x1658d5ae, 0x00c119cf, 0x0348c2bc, 0x11d50ad9,
        0xbd68c615, 0x7d24e531, 0xb868c117, 0x7c20e637,
        0x0f85d77f, 0x1699cc61, 0x0389db73, 0x129dc865,
        0xc940282a, 0xc04c2324, 0xc54c2426, 0xc4482720,
        0x1d181f1a, 0x191c1b1e, 0x15101712, 0x11141316,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    };

    static const uint8_t aes_key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    uint32_t found_key[32 / 4];

#define AES_MIXCOLUMNS_CHECK(word) \
    do { \
        uint32_t _word = (word); \
        uint32_t slow_result = slow_MixColumn(_word); \
        uint32_t fast_result = MixColumn(_word); \
        if (slow_result != fast_result) { \
            printf("Self-test MixColumn(%#x) failed: %#x != %#x\n", _word, slow_result, fast_result); \
        } \
    } while (0)

    AES_MIXCOLUMNS_CHECK(0);
    AES_MIXCOLUMNS_CHECK(0xff);
    AES_MIXCOLUMNS_CHECK(0x01020304);
    AES_MIXCOLUMNS_CHECK(0x89abcdef);
    AES_MIXCOLUMNS_CHECK(0xffffffff);
#undef AES_MIXCOLUMNS_CHECK

    benchmark_MixColumn();

#define AES_CHECK(fun, reverse, arr, len) \
    do { \
        if (!fun(reverse, arr, found_key) || memcmp(aes_key, found_key, len) != 0) { \
            printf("Self-test %s(rev=%s, %s) failed\n", #fun, #reverse, #arr); \
            abort(); \
        } \
        memset(found_key, 0, sizeof(found_key)); \
    } while (0)

    AES_CHECK(aes128_detect_enc, true, aes128_encB, 16);
    AES_CHECK(aes128_detect_enc, false, aes128_encL, 16);

    AES_CHECK(aes192_detect_enc, true, aes192_encB, 24);
    AES_CHECK(aes192_detect_enc, false, aes192_encL, 24);

    AES_CHECK(aes256_detect_enc, true, aes256_encB, 32);
    AES_CHECK(aes256_detect_enc, false, aes256_encL, 32);

    AES_CHECK(aes128_detect_decF, true, aes128_decBF, 16);
    AES_CHECK(aes128_detect_decF, false, aes128_decLF, 16);

    AES_CHECK(aes128_detect_decB, true, aes128_decBB, 16);
    AES_CHECK(aes128_detect_decB, false, aes128_decLB, 16);

    AES_CHECK(aes192_detect_decF, true, aes192_decBF, 24);
    AES_CHECK(aes192_detect_decF, false, aes192_decLF, 24);

    AES_CHECK(aes192_detect_decB, true, aes192_decBB, 24);
    AES_CHECK(aes192_detect_decB, false, aes192_decLB, 24);

    AES_CHECK(aes256_detect_decF, true, aes256_decBF, 32);
    AES_CHECK(aes256_detect_decF, false, aes256_decLF, 32);

    AES_CHECK(aes256_detect_decB, true, aes256_decBB, 32);
    AES_CHECK(aes256_detect_decB, false, aes256_decLB, 32);
#undef AES_CHECK
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
static bool find_aes_keys_in_file(const char *filename)
{
    uint8_t buffer[64 * 1024 + 240];
    FILE *f;
    uint32_t avail = 0;
    uint64_t addr = 0;
    clock_t start_clock = clock();
    double total_time;
    const double MB = 1024.0 * 1024.0;
    uint64_t total = 0;
    unsigned int i;
    bool found_key = false;
    bool has_eof;

    f = fopen(filename, "rmb");
    if (!f) {
        fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        return false;
    }
    has_eof = feof(f);
    while (!has_eof) {
        uint32_t read = sizeof(buffer) - 240 - avail;

        size_t bytes_read = fread(buffer + avail, 1, read, f);
        if (!bytes_read || ferror(f)) {
            fprintf(
               stderr, "Failed to read %u bytes from %s: %s\n",
                read, filename, strerror(errno));
            return false;
        }
        total += bytes_read;
        avail += bytes_read;

        has_eof = feof(f);
        if (has_eof) {
            /* Detect keys in the last chunk of data, by padding with zeros */
            assert(avail + 240 < sizeof(buffer));
            memset(buffer + avail, 0, 240);
            avail += 240;
        }

        /* Maximum size of round keys, for AES256:
         * 4 * (Nb * (Nr + 1)) = 4 * 4 * (14 + 1) = 240
         */
        if (avail >= 240) {
            uint32_t offset = 0;

            while (offset <= avail - 240) {
                uint8_t key[32], test_byte;
                unsigned int key_len;
                uint32_t num_repeat, expanded_key_size;

                /* Optimisation: if the same byte is repeated more than 33 times,
                 * it cannot be an AES key
                 */
                test_byte = buffer[offset];
                for (num_repeat = 1; offset + num_repeat < avail; num_repeat++) {
                    if (buffer[offset + num_repeat] != test_byte)
                        break;
                }
#if ROUND_KEYS_ALIGNED_32BITS
                num_repeat &= ~3U;
#endif
                if (num_repeat >= 33) {
                    /* printf("Skipping large repeat zone @%#" PRIx64 " (%u*\\x%02x)\n",
                     *        addr, num_repeat, test_byte);
                     */
                    offset += num_repeat - 32;
                    addr += num_repeat - 32;
                    continue;
                }

                if ((key_len = aes_detect_enc((const uint32_t *)&buffer[offset], key))) {
                    /* The number of bytes to skip is:
                     * 4 * Nb * (Nr + 1) = 4 * 4 * (Nk + 6 + 1) = 4 * (28 + 4 * Nk) = 4 * (28 + key_size)
                     */
                    expanded_key_size = 4 * (28 + key_len);
                    printf("[%#" PRIx64 "..%#" PRIx64 "] Found AES-%u encryption key: ",
                           addr, addr + expanded_key_size, key_len * 8);
                    for (i = 0; i < key_len; i++) {
                        printf("%02x", key[i]);
                    }
                    printf("\n");
                    found_key = true;
                    offset += expanded_key_size;
                    addr += expanded_key_size;
                } else if ((key_len = aes_detect_dec((const uint32_t *)&buffer[offset], key))) {
                    expanded_key_size = 4 * (28 + key_len);
                    printf("[%#" PRIx64 "..%#" PRIx64 "] Found AES-%d decryption key: ",
                           addr, addr + expanded_key_size, key_len * 8);
                    for (i = 0; i < key_len; i++) {
                        printf("%02x", key[i]);
                    }
                    printf("\n");
                    found_key = true;
                    offset += expanded_key_size;
                    addr += expanded_key_size;
                } else {
#if ROUND_KEYS_ALIGNED_32BITS
                    /* Suppose that the keys are aligned */
                    offset += 4;
                    addr += 4;
#else
                    offset += 1;
                    addr += 1;
#endif
                }
            }
            avail -= offset;
            if (avail)
                memmove(buffer, buffer + offset, avail);
        }
    }
    total_time = (double)(clock() - start_clock) / CLOCKS_PER_SEC;
    printf("Processed %.2f MB in %.0fs, speed = %.2f MB/s\n",
           total / MB, total_time, total / MB / total_time);
    return found_key;
}
#pragma GCC diagnostic pop

int main(int argc, char **argv)
{
    int i;
    bool found_key = false;

    self_test();

    if (argc < 2) {
        printf("Usage: %s FILE [FILE...]\n", argv[0]);
        return 0;
    }

    for (i = 1; i < argc; i++) {
        if (find_aes_keys_in_file(argv[i])) {
            found_key = true;
        }
    }
    return found_key ? 0 : 1;
}
