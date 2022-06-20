#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2021 Nicolas Iooss
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
"""Document some Ethereum smart contract function selectors

Ethereum smart contracts uses Keccak-256 hash function to craft 32-bit selectors
from the interface function names and types.

Keccak is not provided by standard cryptography libraries except PyCryptodome.

In practise, function selectors can be exported from Remix IDE
(https://remix.ethereum.org/)

Similar project:
- https://www.4byte.directory/ (Ethereum Signature Database)
  Source code: https://github.com/pipermerriam/ethereum-function-signature-registry/

@author: Nicolas Iooss
@license: MIT
"""
from pathlib import Path
import re
import struct
import sys

try:
    import Cryptodome.Hash.keccak

    has_cryptodome = True
except (ImportError, OSError):
    # NB. pypy3 fails with OSError "Cannot load native module" instead of ImportError
    has_cryptodome = False


# ERC165 interface hashes
KNOWN_INTERFACE_IDS = (
    # https://eips.ethereum.org/EIPS/eip-137#resolver-specification
    (0x3b3b57de, "EIP-137 ENS Address Resolution"),
    (0x691f3431, "EIP-181 ENS Reverse Resolution"),
    (0x2203ab56, "EIP-205 ENS ABI"),
    (0xf1cb7e06, "EIP-2304 ENS Multichain Address Resolution"),
    (0xc8690233, "EIP-619 ENS Pubkey"),
    (0xd9b67a26, "ERC1155"),
    (0x0e89341c, "ERC1155Metadata_URI"),
    (0x4e2312e0, "ERC1155TokenReceiver"),
    (0x61455567, "ERC1538 Transparent Contract"),
    (0x01ffc9a7, "ERC165"),
    (0xf0083250, "ERC1820Implementer"),
    (0x80ac58cd, "ERC721"),
    (0x780e9d63, "ERC721Enumerable"),
    (0x5b5e139f, "ERC721Metadata"),
    (0xf0083250, "ERC820Implementer"),
)


KNOWN_SELECTORS = []
KNOWN_SELECTORS_BY_ID = {}

def load_selectors():
    global KNOWN_SELECTORS, KNOWN_SELECTORS_BY_ID
    KNOWN_SELECTORS = []
    KNOWN_SELECTORS_BY_ID = {}
    with (Path(__file__).parent / "eth_function_selectors.txt").open("r") as f:
        for line in f:
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            # Match "0x06fdde03 name()"
            matches = re.match(r"^0x([0-9a-f]{8}) (.*)$", line)
            if matches:
                selector_hex, function_prototype = matches.groups()
                selector = int(selector_hex, 16)
                KNOWN_SELECTORS.append([selector, function_prototype, []])
                if selector not in KNOWN_SELECTORS_BY_ID:
                    KNOWN_SELECTORS_BY_ID[selector] = {}
                if function_prototype in KNOWN_SELECTORS_BY_ID[selector]:
                    raise RuntimeError(f"Duplicate selector found {selector:#010x} for {function_prototype!r}")
                KNOWN_SELECTORS_BY_ID[selector][function_prototype] = KNOWN_SELECTORS[-1][2]
                continue

            # Match function APIs
            if re.match(r"^    \S", line):
                assert len(KNOWN_SELECTORS)
                KNOWN_SELECTORS[-1][2].append(line.strip())
                continue

            raise RuntimeError(f"Failed to parse line {line!r}")


load_selectors()


def rol64(x, shift):
    """Rotate X left by the given shift value"""
    assert 0 < shift < 64
    return (x >> (64 - shift)) | ((x << shift) & 0xffffffffffffffff)


# Constants from https://keccak.team/keccak_specs_summary.html
KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
KECCAK_ROTATION_CONSTANTS = (
    (0, 1, 62, 28, 27),
    (36, 44, 6, 55, 20),
    (3, 10, 43, 25, 39),
    (41, 45, 15, 21, 8),
    (18, 2, 61, 56, 14),
)
KECCAK256_BITRATE_BYTES = 136


def keccak256_f_1600(state):
    """Implement Keccak-f[1600] permutation function for Keccak-256"""
    # For Keccak-256, lanes are 64-bit wide, which is 2**6.
    # So there are 12 + 2 * 6 = 24 rounds
    for rc in KECCAK_ROUND_CONSTANTS:
        # Theta step
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        for x in range(5):
            d_x = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1)
            for y in range(5):
                state[x][y] ^= d_x

        # Rho and Pi steps
        b = [[0] * 5 for x in range(5)]
        for x in range(5):
            for y in range(5):
                if x == 0 and y == 0:
                    b[0][0] = state[0][0]
                else:
                    b[y][(2 * x + 3 * y) % 5] = rol64(state[x][y], KECCAK_ROTATION_CONSTANTS[y][x])

        # Chi step
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

        # Iota step
        state[0][0] ^= rc


def keccak256(data):
    """Compute Keccak-256 digest of the given data

    Hash parameters:

        output_size = 256 bits (32 bytes)

        lane_width = 64 bits (8 bytes)

        block_size ("bit rate") = 1088 bits (136 bytes, 17 lanes)

        capacity = 512 bits (64 bytes)

        state_size ("width") = block_size + capacity = 1600 bits (200 bytes, 5x5 lanes)
        (this is "b" in https://keccak.team/keccak_specs_summary.html)
    """

    # Padding
    padlen = KECCAK256_BITRATE_BYTES - (len(data) % KECCAK256_BITRATE_BYTES)
    if padlen == 1:
        padded_data = data + b"\x81"  # Combine 0x01 and 0x80 into a single byte
    else:
        padded_data = data + b"\x01" + b"\0" * (padlen - 2) + b"\x80"
    assert len(padded_data) % KECCAK256_BITRATE_BYTES == 0

    # Update
    state = [[0] * 5 for x in range(5)]
    for i in range(0, len(padded_data), KECCAK256_BITRATE_BYTES):
        # Absorb
        new_lanes = struct.unpack("<17Q", padded_data[i:i + KECCAK256_BITRATE_BYTES])
        for i, value in enumerate(new_lanes):
            y, x = divmod(i, 5)
            state[x][y] ^= value
        keccak256_f_1600(state)

    # Final (Squeeze)
    digest = struct.pack("<4Q", state[0][0], state[1][0], state[2][0], state[3][0])

    if has_cryptodome:
        # Check that our implementation is correct
        reference_digest = Cryptodome.Hash.keccak.new(digest_bits=256, data=data).digest()
        assert reference_digest == digest
    return digest


def eth_selector(function_prototype):
    """Compute a 32-bit selector for an Ethereum smart contract"""
    fct_hash = keccak256(function_prototype.encode("ascii"))
    return int.from_bytes(fct_hash[:4], "big")


def eth_selector_from_json_func(json_function):
    """Parse a JSON contract for a function to compute a selector"""
    function_prototype = json_function["name"] + "("
    for arg_idx, arg in enumerate(json_function["inputs"]):
        if arg_idx >= 1:
            function_prototype += ","
        function_prototype += arg["type"]
    function_prototype += ")"
    return eth_selector(function_prototype), function_prototype


def eth_selectors_from_json_abi(json_abi):
    """Parse a JSON contract ABI to compute all function selectors"""
    return [eth_selector_from_json_func(func) for func in json_abi if func["type"] == "function"]


def show_selectors_from_json_abi(json_abi):
    """Show the selectors from a JSON ABI, describing whether they are known"""
    for selector, function_prototype in eth_selectors_from_json_abi(json_abi):
        known_funcs = KNOWN_SELECTORS_BY_ID.get(selector)
        if known_funcs is None:
            print(f"{selector:#010x}: {function_prototype!r} UNKNOWN")
        elif function_prototype in known_funcs.keys():
            print(f"{selector:#010x}: {function_prototype!r} known")
        else:
            print(f"{selector:#010x}: {function_prototype!r} CONLICT with {sorted(known_funcs.keys())!r}")


def check_keccak256():
    """Check that Keccak256 is implemented correctly"""
    assert keccak256(b"") == bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    # ENS Test vectors from https://eips.ethereum.org/EIPS/eip-137
    namehash_eth = keccak256(b"\0" * 32 + keccak256(b"eth"))
    assert namehash_eth == bytes.fromhex("93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae")
    namehash_foo_eth = keccak256(namehash_eth + keccak256(b"foo"))
    assert namehash_foo_eth == bytes.fromhex("de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f")

    # https://eips.ethereum.org/EIPS/eip-777
    assert keccak256(b"ERC777Token") == bytes.fromhex("ac7fbab5f54a3ca8194167523c6753bfeb96a445279294b6125b68cce2177054")  # noqa
    assert keccak256(b"ERC777TokensSender") == bytes.fromhex("29ddb589b1fb5fc7cf394961c1adf5f8c6454761adf795e67fe149f658abe895")  # noqa
    assert keccak256(b"ERC777TokensRecipient") == bytes.fromhex("b281fc8c12954d22544db45de3159a39272895b169a852b314f9cc762e44c53b")  # noqa

    # https://eips.ethereum.org/EIPS/eip-820
    assert keccak256(b"ERC820_ACCEPT_MAGIC") == bytes.fromhex("f2294ee098a1b324b4642584abe5e09f1da5661c8f789f3ce463b4645bd10aef")  # noqa

    # https://eips.ethereum.org/EIPS/eip-1967
    assert keccak256(b"eip1967.proxy.admin") == bytes.fromhex("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6104")  # noqa
    assert keccak256(b"eip1967.proxy.beacon") == bytes.fromhex("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d51")  # noqa
    assert keccak256(b"eip1967.proxy.implementation") == bytes.fromhex("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbd")  # noqa
    assert keccak256(b"eip1967.proxy.rollback") == bytes.fromhex("4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9144")  # noqa

    # https://eips.ethereum.org/EIPS/eip-3009
    assert keccak256(b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)") == bytes.fromhex("7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267")  # noqa
    assert keccak256(b"ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)") == bytes.fromhex("d099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8")  # noqa
    assert keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)") == bytes.fromhex("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f")  # noqa
    assert keccak256(b"CancelAuthorization(address authorizer,bytes32 nonce)") == bytes.fromhex("158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429")  # noqa

    # https://etherscan.io/address/0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF
    assert keccak256(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)") == bytes.fromhex("6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9")  # noqa

    print("keccak256 self-check passed")


def check_known_selectors():
    """Check that known selectors are correct"""
    # Check eth_selectors_from_json_abi function
    test_contract_abi = [
        {
            "constant": True,
            "inputs": [
                {
                    "name": "interfaceId",
                    "type": "bytes4"
                },
            ],
            "name": "supportsInterface",
            "outputs": [
                {
                    "name": "",
                    "type": "bool"
                },
            ],
            "payable": False,
            "stateMutability": "view",
            "type": "function"
        },
    ]
    assert eth_selectors_from_json_abi(test_contract_abi) == [(0x01ffc9a7, "supportsInterface(bytes4)")]

    last_function_prototype = ""
    for selector, function_prototype, function_apis in KNOWN_SELECTORS:
        # Check the order and the unicity
        if not (last_function_prototype < function_prototype):
            raise ValueError(f"Error: mis-ordered prototype {function_prototype!r} in KNOWN_SELECTORS")
        last_function_prototype = function_prototype

        # Check that the values are in bound
        if not (0 <= selector <= 0xffffffff):
            raise ValueError(f"Error: selector {selector:#010x} is out of bounds for {function_prototype!r}")

        proto_match = re.match(r"^([A-Za-z_][0-9A-Za-z_]*)\(([0-9a-z\[\],]*)\)$", function_prototype)
        if not proto_match:
            raise ValueError(f"Error: invalid function prototype {function_prototype!r}")

        fct_name, fct_argtypes = proto_match.groups()
        if fct_argtypes and not re.match(r"^((address|address\[\]|bool|bytes|bytes\[\]|bytes4|bytes32|string|tuple|tuple\[\]|uint8|uint8\[\]|uint16|uint32|uint64|uint104|uint128|uint256|uint256\[([0-9]*)\]),)+$", fct_argtypes + ","):  # noqa
            raise ValueError(f"Error: unknown type in function prototype {function_prototype!r}")

        for fct_api in function_apis:
            api_match = re.match(r"^[0-9A-Za-z _-]+: function ([A-Za-z_][0-9A-Za-z_]*)\(([0-9A-Za-z_\[\], ]*)\)([0-9A-Za-z_, ()\[\].]*)$", fct_api)  # noqa
            if not api_match:
                # Ignore variables
                if fct_argtypes == "" and " function " not in fct_api:
                    continue
                if " mapping (" + fct_argtypes + " => " in fct_api:
                    continue
                # Hard-code some two-variable mappings for now (to be improved later, if needed...)
                if fct_argtypes == "address,address" and " mapping (address => mapping (address => " in fct_api:
                    continue
                if fct_argtypes == "address,uint32" and " mapping (address => mapping (uint32 => " in fct_api:
                    continue
                if fct_argtypes == "uint32,address" and " mapping (uint32 => mapping (address => " in fct_api:
                    continue
                if fct_argtypes == "uint256" and "[] public " + fct_name in fct_api:
                    continue
                raise ValueError(f"Error: invalid function API {fct_api!r}")
            api_name, api_args, api_remaining = api_match.groups()

            if api_name != fct_name:
                raise ValueError(f"Error: mismatched name for API {fct_api!r}, function {function_prototype!r}")

            # Extract the types from the args
            api_argtypes_list = []
            for arg_with_name in api_args.split(","):
                arg_type = arg_with_name.lstrip(" ").split(" ", 1)[0]
                if arg_type == "uint":  # "uint" is implicitly 256-bit wide
                    arg_type = "uint256"
                if arg_type == "CommitBlockInfo[]":  # "CommitBlockInfo[]" is implicitly a tuple[]
                    arg_type = "tuple[]"
                if arg_type == "ExecuteBlockInfo[]":  # "ExecuteBlockInfo[]" is implicitly a tuple[]
                    arg_type = "tuple[]"
                if arg_type == "IERC20":  # "IERC20" is implicitly an address
                    arg_type = "address"
                if arg_type == "ProofInput":  # "ProofInput" is implicitly a tuple
                    arg_type = "tuple"
                if arg_type == "StoredBlockInfo":  # "StoredBlockInfo" is implicitly a tuple
                    arg_type = "tuple"
                if arg_type == "StoredBlockInfo[]":  # "StoredBlockInfo[]" is implicitly a tuple[]
                    arg_type = "tuple[]"
                if arg_type == "TokenGovernance":  # "TokenGovernance" is implicitly an address
                    arg_type = "address"
                if arg_type == "VerificationKey":  # ",VerificationKey" is implicitly a tuple
                    arg_type = "tuple"
                api_argtypes_list.append(arg_type)
            api_argtypes = ",".join(api_argtypes_list)
            if api_argtypes != fct_argtypes:
                print(f"Error: description type {api_argtypes!r} != Function type {fct_argtypes!r}", file=sys.stderr)
                raise ValueError(f"Error: mismatched argument types for API {fct_api!r}, function {function_prototype!r}")   # noqa

        computed_sel = eth_selector(function_prototype)
        if selector == 0:
            print(f"TODO: add {computed_sel:#010x} for function {function_prototype!r}")
        else:
            assert selector == computed_sel

    # Ensure that all selectors are unique
    defined_selectors = [selector for selector, _, _ in KNOWN_SELECTORS if selector != 0]
    selectors_set = frozenset(defined_selectors)
    assert len(selectors_set) == len(defined_selectors), "Some selectors are duplicated!"
    print(f"Verified {len(KNOWN_SELECTORS)} selectors")


def check_known_interfaces():
    """Check that known interface identifiers are correct"""
    last_iface_id = ""
    for selector, iface_name in KNOWN_INTERFACE_IDS:
        # Check the order and the unicity
        if not (last_iface_id < iface_name):
            raise ValueError(f"Error: mis-ordered interface {iface_name!r} in KNOWN_INTERFACE_IDS")
        last_iface_id = iface_name

        # Check that the values are in bound
        if not (0 <= selector <= 0xffffffff):
            raise ValueError(f"Error: selector {selector:#010x} is out of bounds for {iface_name!r}")

        # Find the selectors from the functions of the interface
        computed_sel = 0
        for fct_selector, function_prototype, function_apis in KNOWN_SELECTORS:
            for function_api in function_apis:
                if function_api.startswith(iface_name + ": "):
                    if fct_selector == 0:
                        fct_selector = eth_selector(function_prototype)
                        print(f"WARNING: using computed selector {fct_selector:#010x} for API {function_api!r}")
                    computed_sel ^= fct_selector
        if selector == 0:
            print(f"TODO: add {computed_sel:#010x} for interface {iface_name!r}")
        elif computed_sel == 0:
            print(f"TODO: unknown functions for interface {iface_name!r} ({selector:#010x})")
        else:
            assert selector == computed_sel

    print(f"Verified {len(KNOWN_INTERFACE_IDS)} interfaces")


if __name__ == "__main__":
    check_keccak256()
    check_known_selectors()
    check_known_interfaces()
