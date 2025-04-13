#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2024 Nicolas Iooss
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
"""Implement STARK curve used in Starknet and address computation

https://docs.starkware.co/starkex/crypto/stark-curve.html
"""
import hashlib
import sys

import bip32_seed_derivation
import ec_tests
from eth_functions_keccak import keccak256

try:
    from typing import Sequence  # noqa: F401
except ImportError:
    pass


# Define the curve used by Starknet
# b is the start of PI plus 379:
#   >>> import mpmath ; mpmath.mp.dps = 76 ; str(mpmath.mp.pi)
#   '3.141592653589793238462643383279502884197169399375105820974944592307816406286'
#   >>> mpmath.mp.dps = 76 * 502 + 100 ; pi_str = str(mpmath.mp.pi).replace(".", "")
#   >>> int(pi_str[0:76]) + 379  # b
#   3141592653589793238462643383279502884197169399375105820974944592307816406665
#   >>> int(pi_str[76 * 2:76 * 3]) % (2**251 + 17 * 2**192 + 1)  # g_x
#   874739451078007766457464989774322083649278607533249481151382481072868806602
STARK_ORDER = 3618502788666131213697322783095070105526743751716087489154079457884512865583
STARK_CURVE = ec_tests.StandardCurve(
    openssl_name="stark",
    p=3618502788666131213697322783095070105623107215331596699973092056135872020481,
    p2=2**251 + 17 * 2**192 + 1,
    a=1,
    b=3141592653589793238462643383279502884197169399375105820974944592307816406665,
    g_x=874739451078007766457464989774322083649278607533249481151382481072868806602,
    g_y=152666792071518830868575557812948353041420400780739481342941381225525861407,
    g_order=STARK_ORDER,
)

ERC2645_STARK_RANDOM_N = 2**256 - (2**256 % STARK_ORDER)

STARKNET_CONTRACT_ADDRESS_PREFIX = 0x535441524b4e45545f434f4e54524143545f41444452455353  # "STARKNET_CONTRACT_ADDRESS"

# Bound with MAX_STORAGE_ITEM_SIZE = 256
STARKNET_ADDR_BOUND = 2**251 - 256


def stark_erc2645_derive(derivation_path, seed):  # type: (str, bytes) -> int
    """Derive a key according to ERC 2645: Hierarchical Deterministic Wallet for Layer-2

    https://github.com/ethereum/ERCs/blob/9f3b27ef75cdf3ee4d2d079af76400737ed03ec2/ERCS/erc-2645.md

    This is called "grinding" in https://community.starknet.io/t/account-keys-and-addresses-derivation-standard/1230
    """
    root_key = bip32_seed_derivation.bip32derive(derivation_path, seed, curve="secp256k1")[0]
    for i in range(256):
        priv_key = int.from_bytes(hashlib.sha256(root_key + i.to_bytes(1, "big")).digest(), "big")
        if priv_key < ERC2645_STARK_RANDOM_N:
            return priv_key % STARK_ORDER
    raise ValueError("Unable to derive a STARK private key")


def starknet_keccak(data):  # type: (bytes) -> int
    """Starknet Keccak is defined as the first 250 bits of the Keccak256 hash

    https://docs.starknet.io/documentation/architecture_and_concepts/Cryptography/hash-functions/#starknet_keccak
    """
    return int.from_bytes(keccak256(data), "big") & 0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff


# Points 0, 2, 2+248=250, 2+252=254, 2+252+248=502 in
# https://github.com/starkware-libs/cairo-lang/blob/v0.13.0/src/starkware/crypto/signature/pedersen_params.json
# and
# https://github.com/starkware-libs/starkex-resources/blob/844ac3dcb1f735451457f7eecc6e37cd96d1cb2d/crypto/starkware/crypto/signature/pedersen_params.json  # noqa
# https://github.com/starkware-libs/starkex-resources/blob/844ac3dcb1f735451457f7eecc6e37cd96d1cb2d/crypto/starkware/crypto/signature/constant_points.json  # noqa
# Also documented in https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html
# Generated by
# https://github.com/starkware-libs/starkex-resources/blob/844ac3dcb1f735451457f7eecc6e37cd96d1cb2d/crypto/starkware/crypto/signature/nothing_up_my_sleeve_gen.py  # noqa
# ... by taking digits of PI by chunks of 76 characters
#     >>> pi_str[76:76 * 2]
#    '2089986280348253421170679821480865132823066470938446095505822317253594081284'
STARKNET_PEDERSEN_SHIFT_POINT = ec_tests.ECPoint(
    STARK_CURVE,
    2089986280348253421170679821480865132823066470938446095505822317253594081284,
    1713931329540660377023406109199410414810705867260802078187082345529207694986,
)
#     >>> int(pi_str[76 * 3:76 * 4]) % (2**251 + 17 * 2**192 + 1) + 1
#     996781205833008774514500082376783249102396023663454813447423147977397232763
STARKNET_PEDERSEN_P0 = ec_tests.ECPoint(
    STARK_CURVE,
    996781205833008774514500082376783249102396023663454813447423147977397232763,
    1668503676786377725805489344771023921079126552019160156920634619255970485781,
)
#     >>> int(pi_str[76 * 4:76 * 5]) % (2**251 + 17 * 2**192 + 1)
#     2251563274489750535117886426533222435294046428347329203627021249169616184184
STARKNET_PEDERSEN_P1 = ec_tests.ECPoint(
    STARK_CURVE,
    2251563274489750535117886426533222435294046428347329203627021249169616184184,
    1798716007562728905295480679789526322175868328062420237419143593021674992973,
)
#     >>> int(pi_str[76 * 5:76 * 6]) + 1
#     2138414695194151160943305727036575959195309218611738193261179310511854807447
STARKNET_PEDERSEN_P2 = ec_tests.ECPoint(
    STARK_CURVE,
    2138414695194151160943305727036575959195309218611738193261179310511854807447,
    113410276730064486255102093846540133784865286929052426931474106396135072156,
)
#     >>> pi_str[76 * 6:76 * 7]
#     '2379962749567351885752724891227938183011949129833673362440656643086021394946'
STARKNET_PEDERSEN_P3 = ec_tests.ECPoint(
    STARK_CURVE,
    2379962749567351885752724891227938183011949129833673362440656643086021394946,
    776496453633298175483985398648758586525933812536653089401905292063708816422,
)


def starknet_pedersen_hash(a, b):  # type: (int, int) -> int
    """Compute the Pedersen hash of two elements

    https://docs.starknet.io/documentation/architecture_and_concepts/Cryptography/hash-functions/
    https://github.com/starkware-libs/cairo-lang/blob/v0.13.0/src/starkware/crypto/signature/fast_pedersen_hash.py
    """
    assert 0 <= a < STARK_CURVE.p
    assert 0 <= b < STARK_CURVE.p
    a_high, a_low = divmod(a, 2**248)
    b_high, b_low = divmod(b, 2**248)
    result = (
        STARKNET_PEDERSEN_SHIFT_POINT
        + STARKNET_PEDERSEN_P0 * a_low
        + STARKNET_PEDERSEN_P1 * a_high
        + STARKNET_PEDERSEN_P2 * b_low
        + STARKNET_PEDERSEN_P3 * b_high
    ).x
    assert result is not None
    return result


def starknet_hash_on_elements(data):  # type: (Sequence[int]) -> int
    """Compute the Pedersen hash of the given list of field elements"""
    result = 0
    for x in data:
        result = starknet_pedersen_hash(result, x)
    return starknet_pedersen_hash(result, len(data))


def starknet_address(
    class_hash, constructor_calldata, salt, deployer_address=0
):  # type: (int, Sequence[int], int, int) -> int
    """Compute the address of a deployed Starknet contract"""
    constructor_calldata_hash = starknet_hash_on_elements(constructor_calldata)
    raw_address = starknet_hash_on_elements(
        [
            STARKNET_CONTRACT_ADDRESS_PREFIX,
            deployer_address,
            salt,
            class_hash,
            constructor_calldata_hash,
        ]
    )
    return raw_address % STARKNET_ADDR_BOUND


def selftests():  # type: () -> None
    """Perform some self tests"""
    assert STARK_CURVE.p == 0x800000000000011000000000000000000000000000000000000000000000001
    assert STARK_CURVE.p.bit_length() == 252
    assert STARK_ORDER == 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
    assert STARK_CURVE.g.order == 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
    assert STARK_ORDER.bit_length() == 252
    assert STARK_CURVE.g * (STARK_ORDER - 1) + STARK_CURVE.g == ec_tests.INFINITY

    # Ensure the randomness from ERC-2645 key derivation is indeed uniform
    secp256k1_order = ec_tests.SECP256K1.g.order
    assert secp256k1_order is not None
    assert ERC2645_STARK_RANDOM_N == secp256k1_order - (secp256k1_order % STARK_ORDER)

    # Check Starknet Keccak
    assert starknet_keccak(b"supportsInterface") == 0x29e211664c0b63c79638fbea474206ca74016b3e9a3dc4f9ac300ffd8bdf2cd
    assert starknet_keccak(b"get_public_key") == 0x1a35984e05126dbecb7c3bb9929e7dd9106d460c59b1633739a5c733a5fb13b
    assert starknet_keccak(b"AccountInitialized") == 0xd876503fb434f7517a7b4ae8d0d5fba27e2fa7b1a9f200deb935316f46fcc3
    assert starknet_keccak(b"Upgraded") == 0x2db340e6c609371026731f47050d3976552c89b4fbb012941663841c59d1af3

    # Check Pedersen hash function
    max_value = 0x800000000000011000000000000000000000000000000000000000000000000
    assert STARK_CURVE.p == max_value + 1
    assert starknet_pedersen_hash(0, 0) == 2089986280348253421170679821480865132823066470938446095505822317253594081284
    assert starknet_pedersen_hash(1, 0) == 1089549915800264549621536909767699778745926517555586332772759280702396009108
    assert (
        starknet_pedersen_hash(max_value, 0)
        == 1672084881017457057854213199329225616426954930355015385355866035553274296404
    )
    assert starknet_pedersen_hash(0, 1) == 2001140082530619239661729809084578298299223810202097622761632384561112390979
    assert (
        starknet_pedersen_hash(0, max_value)
        == 605918279616184729963889018663317638716626921162701275938234640203264537182
    )
    assert starknet_pedersen_hash(1, 1) == 1321142004022994845681377299801403567378503530250467610343381590909832171180
    assert (
        starknet_pedersen_hash(max_value, max_value)
        == 3232555749487190471763097992898089327242482272407513295348046886353176778606
    )

    # Test cases from
    # https://github.com/software-mansion/starknet.py/blob/f992bc853dfb5dc295a4e365fe30f8cfe4b69d0e/starknet_py/hash/storage_test.py#L8  # noqa
    assert starknet_keccak(b"a") == 1247650000417123719142308899207783949116295758836619114717800638088997106123
    assert starknet_pedersen_hash(starknet_pedersen_hash(starknet_pedersen_hash(starknet_keccak(b"a"), 123), 456), 789) == 404238469756318355939104484967681930221679732602307291786242730553081970461
    assert starknet_keccak(b"a" * 32) == 1639766182393060139699536825713183380146349476460289054183902158918808727042
    assert starknet_pedersen_hash(starknet_pedersen_hash(starknet_pedersen_hash(starknet_pedersen_hash(starknet_keccak(b"a" * 64), 32), 64), 128), 256) == 1170278195143236183253456127997214153696661952271500757743981570818429662143
    assert starknet_keccak(b"storage_name") == 268122074306748686933226222576463058414657484382047525198367644523311212699
    assert starknet_pedersen_hash(starknet_pedersen_hash(starknet_pedersen_hash(starknet_keccak(b"storage_name"), 2), 2), 2) == 1815994203838325690189267524162006605165509742004447508084124379729518768247
    assert starknet_pedersen_hash(starknet_keccak(b"another_storage_name"), 3) == 3209489259786454249517264229792296517536124865381513663576107903160324151127

    # Test cases from
    # https://github.com/starkware-libs/cairo/blob/v2.5.4/crates/cairo-lang-starknet/src/plugin/plugin_test_data/components/component  # noqa
    assert starknet_keccak(b"data") == 0x354f1c2d0eb5771cd5bf67a6689fcd6eed9444d91a39e5ef32a9b4ae5ca14ff
    assert starknet_keccak(b"map") == 0x1af9e30ee4fed507d9432e0f1308eb5bd12221bef97071a48d86951102231be
    assert starknet_keccak(b"my_type_var") == 0x1d7ac842e8e2a1c4fd94662d0a812cd378294e5156fee62dafbd49a010246c7

    # Test case with #[substorage(v0)] from
    # https://github.com/starkware-libs/cairo/blob/4ef4d3f913594658aa0f241ebd105e7b8dbe9ce7/crates/cairo-lang-starknet/cairo_level_tests/contracts/with_erc20.cairo  # noqa
    # https://github.com/starkware-libs/cairo/blob/4ce11966cbdc3fb4bfc2d102ff5cc42567ccd324/crates/cairo-lang-starknet/cairo_level_tests/components/erc20.cairo  # noqa
    # https://github.com/starkware-libs/cairo/blob/4ef4d3f913594658aa0f241ebd105e7b8dbe9ce7/crates/cairo-lang-starknet/test_data/with_erc20.sierra # noqa
    # Used for example in Sierra (Safe Intermediate Representation) for "self.name.read()":
    # https://github.com/starkware-libs/cairo/blob/4ef4d3f913594658aa0f241ebd105e7b8dbe9ce7/crates/cairo-lang-starknet/test_data/with_erc20.sierra#L3552-L3556  # noqa
    #   storage_base_address_const<1528802474226268325865027367859591458315299653151958663884057507666229546336>() -> ([3]); // 3027
    #   storage_address_from_base([3]) -> ([4]); // 3028
    #   u32_const<0>() -> ([5]); // 3029
    #   store_temp<u32>([5]) -> ([5]); // 3030
    #   store_temp<StorageAddress>([4]) -> ([4]); // 3031
    #   storage_read_syscall([0], [1], [5], [4]) { fallthrough([6], [7], [8]) 3039([9], [10], [11]) };
    assert starknet_keccak(b"name") == 1528802474226268325865027367859591458315299653151958663884057507666229546336
    assert starknet_keccak(b"symbol") == 944713526212149105522785400348068751682982210605126537021911324578866405028
    assert starknet_keccak(b"decimals") == 134830404806214277570220174593674215737759987247891306080029841794115377321
    assert starknet_keccak(b"total_supply") == 603278275252936218847294002513349627170936020082667936993356353388973422646
    # Field defined by: balances: LegacyMap::<ContractAddress, u256>
    # https://github.com/starkware-libs/cairo/blob/4ef4d3f913594658aa0f241ebd105e7b8dbe9ce7/crates/cairo-lang-starknet/test_data/with_erc20.sierra#L4756-L4770
    #   drop<test::erc20::balances::ComponentMemberState>([2]) -> (); // 4232
    #   contract_address_to_felt252([3]) -> ([4]); // 4233
    #   felt252_const<1065622543624526936256554561967983185612257046533136611876836524258158810564>() -> ([5]); // 4234
    #   struct_construct<core::pedersen::HashState>([5]) -> ([6]); // 4235
    #   struct_deconstruct<core::pedersen::HashState>([6]) -> ([7]); // 4236
    #   store_temp<felt252>([7]) -> ([7]); // 4237
    #   pedersen([1], [7], [4]) -> ([8], [9]); // 4238
    #   struct_construct<core::pedersen::HashState>([9]) -> ([10]); // 4239
    #   struct_deconstruct<core::pedersen::HashState>([10]) -> ([11]); // 4240
    #   store_temp<felt252>([11]) -> ([11]); // 4241
    #   storage_base_address_from_felt252([0], [11]) -> ([12], [13]); // 4242
    #   store_temp<RangeCheck>([12]) -> ([14]); // 4243
    #   store_temp<Pedersen>([8]) -> ([15]); // 4244
    #   store_temp<StorageBaseAddress>([13]) -> ([16]); // 4245
    #   return([14], [15], [16]); // 4246
    assert starknet_keccak(b"balances") == 1065622543624526936256554561967983185612257046533136611876836524258158810564
    # Field defined by: allowances: LegacyMap::<(ContractAddress, ContractAddress), u256>
    # https://github.com/starkware-libs/cairo/blob/4ef4d3f913594658aa0f241ebd105e7b8dbe9ce7/crates/cairo-lang-starknet/test_data/with_erc20.sierra#L4771-L4791  # noqa
    #   drop<test::erc20::allowances::ComponentMemberState>([2]) -> (); // 4247
    #   struct_deconstruct<Tuple<ContractAddress, ContractAddress>>([3]) -> ([4], [5]); // 4248
    #   contract_address_to_felt252([4]) -> ([6]); // 4249
    #   felt252_const<337994139936370667767799129369552596157394447336989834104582481799883947719>() -> ([7]); // 4250
    #   struct_construct<core::pedersen::HashState>([7]) -> ([8]); // 4251
    #   struct_deconstruct<core::pedersen::HashState>([8]) -> ([9]); // 4252
    #   store_temp<felt252>([9]) -> ([9]); // 4253
    #   pedersen([1], [9], [6]) -> ([10], [11]); // 4254
    #   contract_address_to_felt252([5]) -> ([12]); // 4255
    #   struct_construct<core::pedersen::HashState>([11]) -> ([13]); // 4256
    #   struct_deconstruct<core::pedersen::HashState>([13]) -> ([14]); // 4257
    #   store_temp<felt252>([14]) -> ([14]); // 4258
    #   pedersen([10], [14], [12]) -> ([15], [16]); // 4259
    #   struct_construct<core::pedersen::HashState>([16]) -> ([17]); // 4260
    #   struct_deconstruct<core::pedersen::HashState>([17]) -> ([18]); // 4261
    #   store_temp<felt252>([18]) -> ([18]); // 4262
    #   storage_base_address_from_felt252([0], [18]) -> ([19], [20]); // 4263
    #   store_temp<RangeCheck>([19]) -> ([21]); // 4264
    #   store_temp<Pedersen>([15]) -> ([22]); // 4265
    #   store_temp<StorageBaseAddress>([20]) -> ([23]); // 4266
    #   return([21], [22], [23]); // 4267
    # https://github.com/starkware-libs/cairo/blob/4ce11966cbdc3fb4bfc2d102ff5cc42567ccd324/crates/cairo-lang-starknet/test_data/ownable_erc20.sierra
    assert starknet_keccak(b"owner") == 907111799109225873672206001743429201758838553092777504370151546632448000192


def test_braavos_challenge_feb2024(verbose=False):  # type: (bool) -> None
    """Test using data from the Braavos challenge, which occured in February 2024

    https://braavos.app/capture-the-flag-challenge-grab-150k/
    https://twitter.com/myBraavos/status/1754918604183568513
    https://twitter.com/myBraavos/status/1756231357041172708
    """
    mnemonics = "family nature fashion project scrub obscure bus crop coconut ship person winner"
    pubkeys = [
        0x32b3b760040053a3cbfb32956baebd2ebe9b5eea8bd56b2f75191c2e8ffd850,
        0x2dc5433e2123019b681257067efe0a6af69b2e1d0f88b80c30dbab2ef81a1ce,
        0x043c6f145b676c1522297e2a55a8c0875eb81f55fe8ee615453fe1b2f3c391b,
        0x2328a100a6c335c345566634cb6e88db28818e4afa278ee59c0bdbc05e2d276,
        0x25578cb275b3b15be4e0423a2df31eaf3660f7cd35ff7e847138e3b5756cf06,
        0x396723772c663848b64a9bc13da23ada3afdbeeaf91664ae492fd178b760de7,
        0x7fb3840b026007255e3ffbebb90e8caa0dd9f8162824e3ebecc4a1155456449,
        0x4a5bfaba7e838b890dee1dfbea08b0d213de554040a539f7d143f3d8fa6adab,
        0x32c6f40a752fd8812ebef1a3e758c2b108b7cce4d436d2780c1473847193fc6,
        0x45d8a420d1b14310801ce4c562f867c7171cdee921e861a7bed5cb6aafc28c0,
        0x1848c0c2d0d9f5b03a12b01a69f21c7b6c1f19a943b391e1d98244a893dcc50,
    ]
    assert len(pubkeys) == 11

    # Contract addresses can be displayed online with the Starkscan explorer:
    # https://starkscan.co/contract/0x05411c4fa52c0ca5de38b1af0329fcb71c38761af7c828da83dc5bd495e4571e
    addresses = [
        0x05411c4fa52c0ca5de38b1af0329fcb71c38761af7c828da83dc5bd495e4571e,
        0x0377dbca79e01d5054689ab5f728e5e31bdc5383702b07779125699f07cde9b2,
        0x050c7939647270edebde0929dbd8bb9f4fe586495d4e253af33c0698d7f3b1b9,
        0x01af9fcb8b2cf83d63a98a2e9f9304eb702bb774ca6fdc9b4d7fcb77f062b12b,
        0x022bd1fa1c4e4972080e4b630d934054eb0736225347ad38c217007bab36e727,
        0x05e148b9bd8ecd54717daf7bee332110dbf908ca68cef0c11ccb45191399938f,
        0x050bf582e27349e5b8b6e65cf988e11242ebc53a03fae5cd124bc2859686d1a6,
        0x075f3c39c96f4de1f69c609bcf013085a7f4f021dd58ed056a4fec7254974196,
        0x014e26ac7e387f7d1ea6ef6dbd33f37dbb6346b46ab7d44a7f5ce6c0e39037f6,
        0x037b098f9718eab2a78b5b26bbe0572d1352430b441b8c72129d4da97be6b4ba,
        0x0127c166c80508f807c4068dcb3135c34a676355a071f602c2bfd19e628edd45,
    ]
    assert len(addresses) == 11

    seed = bip32_seed_derivation.bip39toseed(mnemonics)
    for account_idx in range(11):
        # Derive for Braavos wallet
        # SLIP-44 coin 9004 is Starknet
        # https://github.com/satoshilabs/slips/blob/67570dd0b1cc8095c05b495aa349ce7fe2681057/slip-0044.md
        priv_key = stark_erc2645_derive("m/44'/9004'/0'/0/" + str(account_idx), seed)
        pubkey = STARK_CURVE.g * priv_key
        if verbose:
            print(f"Braavos account {account_idx}+1={account_idx+1}: pk {pubkey.x:#065x}")
        assert pubkey.x == pubkeys[account_idx]

        if account_idx == 0:
            # Braavos wallet class hash
            class_hash = 0x013bfe114fb1cf405bfc3a7f8dbe2d91db146c17521d40dcf57e16d6b59fa8e6
            constructor_calldata = [pubkey.x]
        else:
            # Proxy account, with paramaters: implementation_address, initializer_selector, calldata_len, calldata
            class_hash = 0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e
            constructor_calldata = [
                0x5aa23d5bb71ddaa783da7ea79d405315bafa7cf0387a74f4593578c3e9e6570,
                0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a,
                1,
                pubkey.x,
            ]

        address = starknet_address(
            class_hash=class_hash,
            constructor_calldata=constructor_calldata,
            salt=pubkey.x,
            deployer_address=0,
        )
        if verbose:
            print(f"  https://starkscan.co/contract/{address:#065x}")
        assert address == addresses[account_idx]

    # Storage slots in https://starkscan.co/contract/0x0377dbca79e01d5054689ab5f728e5e31bdc5383702b07779125699f07cde9b2#contract-storage
    # From source https://github.com/myBraavos/braavos-account-cairo/tree/a781740881ab73449865b505d0cdc8c22005c255
    # and newer version https://github.com/myBraavos/braavos-account-cairo/blob/e8753ad1eaba0f96abe1f85684c27c3223eaa062
    assert 0x0010064c6264bc3361adf2b26fd01272239473906cb7bbc183b1819e75188451 == starknet_keccak(b"Account_storage_migration_version")
    assert 0x00b4243e5c50fe8b1ec72787e8bdc6875d9e0ac2cf01c216a38498dad9576672 == starknet_keccak(b"Account_execution_time_delay_sec")
    assert 0x00ee2b6c840729051a0d06a623ff093dcc01e03f2e0c0e07114ac2440394b889 == starknet_keccak(b"Proxy_admin")
    assert 0x01f23302c120008f28b62f70efc67ccd75cfe0b9631d77df231d78b0538dcd8f == starknet_pedersen_hash(starknet_keccak(b"Account_signers"), 0)
    assert 0x01f23302c120008f28b62f70efc67ccd75cfe0b9631d77df231d78b0538dcd93 == starknet_pedersen_hash(starknet_keccak(b"Account_signers"), 0) + 4
    assert 0x022d694246e636c185ebc6e470a72a81b23e8f764658482e4ba6f71b3e89f4f6 == starknet_keccak(b"Account_signers_max_index")
    assert 0x024c6bef42599cac5df32454d99626b76317370946eaa718f2c2b271d2470fd6 == starknet_keccak(b"Account_deferred_remove_signer")
    assert 0x024c6bef42599cac5df32454d99626b76317370946eaa718f2c2b271d2470fd7 == starknet_keccak(b"Account_deferred_remove_signer") + 1
    assert 0x03620fbea5d97f752376a24c4bd8d3593a702443e6fd379134cda24c6652bf46 == starknet_keccak(b"Account_signers_num_hw_signers")
    assert 0x038036e4af1d77f33f0c5cd33a3353e2a5b2265dd26031df7d7c79297f908457 == starknet_keccak(b"stark_signers")
    assert 0x0387c153462d309d4b5a1fc5f90e85bc59eeb2094b2fcef46513ea5f1d1c9b85 == starknet_keccak(b"Proxy_initialized")
    assert 0x03ad34fad732b51fe0d1a1350f149f21a0cf14a9382c9c6e7b262c4e0c8dbf18 == starknet_keccak(b"Proxy_implementation_address")
    assert 0x05ffe276c23808c8e585d28e5bf3ed428cab52a3679435f3cc74d4d876db0855 == starknet_pedersen_hash(starknet_keccak(b"Account_signers"), 1)
    assert 0x05ffe276c23808c8e585d28e5bf3ed428cab52a3679435f3cc74d4d876db0856 == starknet_pedersen_hash(starknet_keccak(b"Account_signers"), 1) + 1
    assert 0x05ffe276c23808c8e585d28e5bf3ed428cab52a3679435f3cc74d4d876db0857 == starknet_pedersen_hash(starknet_keccak(b"Account_signers"), 1) + 2
    assert 0x05ffe276c23808c8e585d28e5bf3ed428cab52a3679435f3cc74d4d876db0858 == starknet_pedersen_hash(starknet_keccak(b"Account_signers"), 1) + 3
    assert 0x05ffe276c23808c8e585d28e5bf3ed428cab52a3679435f3cc74d4d876db0859 == starknet_pedersen_hash(starknet_keccak(b"Account_signers"), 1) + 4

    # Storage slots in https://starkscan.co/contract/0x05411c4fa52c0ca5de38b1af0329fcb71c38761af7c828da83dc5bd495e4571e#contract-storage
    assert 0x00981e5d5d396dbd43a5a4ef76022a975d99e21237fbc8c6eeb96185fd117170 == starknet_keccak(b"deferred_req_time_delay")
    assert 0x0130f455c63540817905ad6f967e022f596bf298a715bb8bb37c40d10fb51a26 == starknet_keccak(b"secp256r1_signers")
    assert 0x038036e4af1d77f33f0c5cd33a3353e2a5b2265dd26031df7d7c79297f908457 == starknet_keccak(b"stark_signers")
    assert 0x03d799152caa65fc75710f2fd193a768a23f74f952b72e07059fc52059cc64dc == starknet_keccak(b"deferred_remove_signer_req")


if __name__ == "__main__":
    selftests()
    test_braavos_challenge_feb2024(verbose="--verbose" in sys.argv)
