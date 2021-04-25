#!/usr/bin/env python3
"""Compute the CallSiteTypeId of some function types for clang CFI (Control Flow Integrity).

When calling a function indirectly, clang could introduce a call to a function
which checks the type of the called function:

    void __cfi_check(uint64 CallSiteTypeId, void *TargetAddr, void *DiagData)
    void __cfi_slowpath(uint64 CallSiteTypeId, void *TargetAddr)
    void __cfi_slowpath_diag(uint64 CallSiteTypeId, void *TargetAddr, void *DiagData)

The CallSiteTypeId is the MD5 of the typeinfo string, truncated to a 64-bit
integer.

Documentation:

* https://clang.llvm.org/docs/ControlFlowIntegrityDesign.html
* https://struct.github.io/cross_dso_cfi.html
* https://github.com/llvm-mirror/clang/blob/release_80/lib/CodeGen/CodeGenModule.cpp#L1159-L1164
  Computation: llvm::ConstantInt::get(Int64Ty, llvm::MD5Hash(MDS->getString()));
"""
import hashlib
import subprocess
import sys


KNOWN_TYPEINFO_NAMES = (
    # Basic types
    ("_ZTSa", 0xc4adbb09d853c709, "signed char"),
    ("_ZTSb", 0x0419a17afc467250, "bool"),
    ("_ZTSc", 0xab9b79bbaecc55c1, "char"),
    ("_ZTSd", 0x8a08189bc493b04a, "double"),
    ("_ZTSe", 0x3f854339f3ac20f9, "long double"),
    ("_ZTSf", 0x23c0f1ed28f3cc03, "float"),
    ("_ZTSg", 0x5f17fe5918364716, "__float128"),
    ("_ZTSh", 0xbf7dfd2059d35aa4, "unsigned char"),
    ("_ZTSi", 0xf683aa7bca520998, "int"),
    ("_ZTSj", 0xaf45dda182130b19, "unsigned int"),
    ("_ZTSl", 0xcfb829a70b269ec2, "long"),
    ("_ZTSm", 0xca1f38b788aa7176, "unsigned long"),
    ("_ZTSn", 0x0c7feb997636baa9, "__int128"),
    ("_ZTSo", 0xf1d24b5b970dbef0, "unsigned __int128"),
    ("_ZTSs", 0x52e8e3b548517584, "short"),
    ("_ZTSt", 0xaceb8bc3ab2fb3b1, "unsigned short"),
    ("_ZTSv", 0xb22fd0e46e167541, "void"),
    ("_ZTSw", 0xa15acd2d4b3ba9f1, "wchar_t"),
    ("_ZTSx", 0xdc031bdfaff3779f, "long long"),
    ("_ZTSy", 0x1639a2a5e21b1916, "unsigned long long"),
    ("_ZTSz", 0xfd5f5dc16053a2a4, "..."),

    # Two letters, with type modifiers. There are also possible three-letter combinations
    ("_ZTSra", 0x88f6d4d6eab1df2e, "signed char restrict"),
    ("_ZTSrb", 0xad687ff06e782ded, "bool restrict"),
    ("_ZTSrc", 0xdba4d1ceedf018fb, "char restrict"),
    ("_ZTSrd", 0x0430abdad346705c, "double restrict"),
    ("_ZTSre", 0x8dc39e9e89741fce, "long double restrict"),
    ("_ZTSrf", 0x957e6ed91e3c376a, "float restrict"),
    ("_ZTSrg", 0x075bdd5ca07eed4b, "__float128 restrict"),
    ("_ZTSrh", 0x789e71a51827091f, "unsigned char restrict"),
    ("_ZTSri", 0xe2595d5c10100d92, "int restrict"),
    ("_ZTSrj", 0xa24f106305a9cbf1, "unsigned int restrict"),
    ("_ZTSrl", 0x4d1bbc1c9df5e7e0, "long restrict"),
    ("_ZTSrm", 0x284a24a02095fd7d, "unsigned long restrict"),
    ("_ZTSrn", 0x72428e9cb7967f30, "__int128 restrict"),
    ("_ZTSro", 0x86a3183f853ace33, "unsigned __int128 restrict"),
    ("_ZTSrs", 0x73de5486e596e42b, "short restrict"),
    ("_ZTSrt", 0x54a1ef2e905ff10a, "unsigned short restrict"),
    ("_ZTSrv", 0x51b28ed0942b3fce, "void restrict"),
    ("_ZTSrw", 0xd23b046f37e877e5, "wchar_t restrict"),
    ("_ZTSrx", 0xb728bad8284b61a0, "long long restrict"),
    ("_ZTSry", 0x38d32f23243bcd4a, "unsigned long long restrict"),
    ("_ZTSrz", 0xbb41cedf5e8065bf, "... restrict"),

    ("_ZTSCa", 0x4ff5d986e474fad1, "signed char _Complex"),
    ("_ZTSCb", 0x4816f8ad6979290e, "bool _Complex"),
    ("_ZTSCc", 0x7fa8f59b01ebf074, "char _Complex"),
    ("_ZTSCd", 0x845c45c213cadb6a, "double _Complex"),
    ("_ZTSCe", 0x64acad2a49d24cc5, "long double _Complex"),
    ("_ZTSCf", 0x60a787870523ccec, "float _Complex"),
    ("_ZTSCg", 0x3f4c7013309344bf, "__float128 _Complex"),
    ("_ZTSCh", 0x569fad76e8daf47e, "unsigned char _Complex"),
    ("_ZTSCi", 0x2361d577e2e092ee, "int _Complex"),
    ("_ZTSCj", 0xbb363c22fb04e032, "unsigned int _Complex"),
    ("_ZTSCl", 0xdd3fc3e7a36ca4b9, "long _Complex"),
    ("_ZTSCm", 0x689f36a7b3b0d664, "unsigned long _Complex"),
    ("_ZTSCn", 0xcf583a5324ef7dae, "__int128 _Complex"),
    ("_ZTSCo", 0x219cb01a36368fb7, "unsigned __int128 _Complex"),
    ("_ZTSCs", 0xfe00a35d68300ff3, "short _Complex"),
    ("_ZTSCt", 0x251b44bbe7a85f0b, "unsigned short _Complex"),
    ("_ZTSCv", 0x03ff01e73a793c5c, "void _Complex"),
    ("_ZTSCw", 0x298f4f7f9542de9a, "wchar_t _Complex"),
    ("_ZTSCx", 0xc57f64d471fe4abe, "long long _Complex"),
    ("_ZTSCy", 0xd1c0634e6902a868, "unsigned long long _Complex"),
    ("_ZTSCz", 0xe38311a225a60dba, "... _Complex"),

    ("_ZTSDa", 0xfb10158115c295e9, "auto"),
    ("_ZTSDc", 0x5d8409bc536008a9, "decltype(auto)"),
    ("_ZTSDd", 0xd083f9d47886cafd, "decimal64"),
    ("_ZTSDe", 0xb5cf4b4111bdd3d3, "decimal128"),
    ("_ZTSDf", 0xe1e952e08c0ad611, "decimal32"),
    ("_ZTSDh", 0x3f7ef17cc32b0dd4, "half"),
    ("_ZTSDi", 0x503a7dc8daab6211, "char32_t"),
    ("_ZTSDn", 0xb22d832571e7f23f, "decltype(nullptr)"),
    ("_ZTSDs", 0xcc352155d790d4ca, "char16_t"),
    ("_ZTSDu", 0x6b9922ed202cc991, "char8_t"),

    ("_ZTSGa", 0x002501a685a95653, "signed char _Imaginary"),
    ("_ZTSGb", 0x6ab5cd51f02c10c7, "bool _Imaginary"),
    ("_ZTSGc", 0xc204b0de682e3c32, "char _Imaginary"),
    ("_ZTSGd", 0xe100c2d34d960fb2, "double _Imaginary"),
    ("_ZTSGe", 0x157cb03cb1192149, "long double _Imaginary"),
    ("_ZTSGf", 0xac7f2b45e7f73f1d, "float _Imaginary"),
    ("_ZTSGg", 0x2d9d5727947746cf, "__float128 _Imaginary"),
    ("_ZTSGh", 0x5dc5f758dd6a03c0, "unsigned char _Imaginary"),
    ("_ZTSGi", 0xdcdf69d9389c2c4e, "int _Imaginary"),
    ("_ZTSGj", 0xd3e11d44de988bd7, "unsigned int _Imaginary"),
    ("_ZTSGl", 0x8a88d8c9f3c559a5, "long _Imaginary"),
    ("_ZTSGm", 0x585ea9eab5c9db23, "unsigned long _Imaginary"),
    ("_ZTSGn", 0x7d180229bea09e6c, "__int128 _Imaginary"),
    ("_ZTSGo", 0x32096bfc85fd2c21, "unsigned __int128 _Imaginary"),
    ("_ZTSGs", 0x5cb4f3abbb9d93ed, "short _Imaginary"),
    ("_ZTSGt", 0x726b1738c858485d, "unsigned short _Imaginary"),
    ("_ZTSGv", 0x0367259a0ed71ac3, "void _Imaginary"),
    ("_ZTSGw", 0xf0269ef5f72cdcd3, "wchar_t _Imaginary"),
    ("_ZTSGx", 0xf4e5046d5c0fa4da, "long long _Imaginary"),
    ("_ZTSGy", 0xe6de9a2c91f3e165, "unsigned long long _Imaginary"),
    ("_ZTSGz", 0x01f833e8ffbe3fc6, "... _Imaginary"),

    ("_ZTSKa", 0xabc0ed19f744a038, "signed char const"),
    ("_ZTSKb", 0x7ffbb567d1d339df, "bool const"),
    ("_ZTSKc", 0x85276d0a7ead5d42, "char const"),
    ("_ZTSKd", 0x0e1778364c39409a, "double const"),
    ("_ZTSKe", 0xa582913a0d15d618, "long double const"),
    ("_ZTSKf", 0xd4037182ba82510e, "float const"),
    ("_ZTSKg", 0x39c4f4d9e1fbbc1c, "__float128 const"),
    ("_ZTSKh", 0x2edf4cf792b50b63, "unsigned char const"),
    ("_ZTSKi", 0x39f908a442235703, "int const"),
    ("_ZTSKj", 0x6c17cf52f410f643, "unsigned int const"),
    ("_ZTSKl", 0x92248e035d6df962, "long const"),
    ("_ZTSKm", 0xabcc875caef95524, "unsigned long const"),
    ("_ZTSKn", 0xe365174c6c12b68d, "__int128 const"),
    ("_ZTSKo", 0xeba7a5232d519954, "unsigned __int128 const"),
    ("_ZTSKs", 0xc112ecde455d0d53, "short const"),
    ("_ZTSKt", 0xaf75564e4dabb2fd, "unsigned short const"),
    ("_ZTSKv", 0x9a1f80bc01aa1992, "void const"),
    ("_ZTSKw", 0x46e4b3e37c328aac, "wchar_t const"),
    ("_ZTSKx", 0xe18a330148ba17a0, "long long const"),
    ("_ZTSKy", 0x6b13850dd23c6414, "unsigned long long const"),
    ("_ZTSKz", 0xc5f549a89d928014, "... const"),

    ("_ZTSOa", 0xeb860e8b9bf796f2, "signed char&&"),
    ("_ZTSOb", 0x36dcc42c51f8ce45, "bool&&"),
    ("_ZTSOc", 0xec535dd75a942b2e, "char&&"),
    ("_ZTSOd", 0x16719ea35b115bf4, "double&&"),
    ("_ZTSOe", 0x9c1cb225dfc3d1c2, "long double&&"),
    ("_ZTSOf", 0xd8026b365181127a, "float&&"),
    ("_ZTSOg", 0x223e0cf969f3b559, "__float128&&"),
    ("_ZTSOh", 0x8893b9a6775b07d6, "unsigned char&&"),
    ("_ZTSOi", 0x0aa58d7cad6521d7, "int&&"),
    ("_ZTSOj", 0x39db5857bad7a03a, "unsigned int&&"),
    ("_ZTSOl", 0xd1b9c5dfc2050732, "long&&"),
    ("_ZTSOm", 0x0db2ee5a089f036c, "unsigned long&&"),
    ("_ZTSOn", 0x7a0a351a340ccbd9, "__int128&&"),
    ("_ZTSOo", 0x6e86c105a8f0391f, "unsigned __int128&&"),
    ("_ZTSOs", 0x2e905f57a711fd25, "short&&"),
    ("_ZTSOt", 0x4950c70a4203a611, "unsigned short&&"),
    ("_ZTSOv", 0x230a51c2608f9459, "void&&"),
    ("_ZTSOw", 0x626528e1b4760c9b, "wchar_t&&"),
    ("_ZTSOx", 0xd9e02a534872e9c8, "long long&&"),
    ("_ZTSOy", 0xcd855270d4a250f8, "unsigned long long&&"),
    ("_ZTSOz", 0x7260fc65586ecf99, "...&&"),

    ("_ZTSPa", 0x8635cc040d3657b2, "signed char*"),
    ("_ZTSPb", 0x13fdb83481f296de, "bool*"),
    ("_ZTSPc", 0x4354be10a95f6f56, "char*"),
    ("_ZTSPd", 0xb2aec1ebd38039b3, "double*"),
    ("_ZTSPe", 0x220151204571f54d, "long double*"),
    ("_ZTSPf", 0xd51219164b6fedf8, "float*"),
    ("_ZTSPg", 0xa254bc164211ff9f, "__float128*"),
    ("_ZTSPh", 0x78879614b536173f, "unsigned char*"),
    ("_ZTSPi", 0x2c63f017ee3137fa, "int*"),
    ("_ZTSPj", 0xdbeb3aea87d75b94, "unsigned int*"),
    ("_ZTSPl", 0xefbdc16dd603348c, "long*"),
    ("_ZTSPm", 0xaa3b3e1b96a71b17, "unsigned long*"),
    ("_ZTSPn", 0x7e458b934343ad6c, "__int128*"),
    ("_ZTSPo", 0xb1e2eac746277e20, "unsigned __int128*"),
    ("_ZTSPs", 0x19364f1324623c57, "short*"),
    ("_ZTSPt", 0x63bcaa4e8556da50, "unsigned short*"),
    ("_ZTSPv", 0x661011fb9b7b39df, "void*"),
    ("_ZTSPw", 0x1cc387d7912b1247, "wchar_t*"),
    ("_ZTSPx", 0xcb07f6f25c7cd205, "long long*"),
    ("_ZTSPy", 0x18ece82cfe42ca19, "unsigned long long*"),
    ("_ZTSPz", 0x4575885118c4af71, "...*"),

    ("_ZTSRa", 0x5b40db66f5be6b6c, "signed char&"),
    ("_ZTSRb", 0x7919e6148bf9c3af, "bool&"),
    ("_ZTSRc", 0xb18787ea5d13235b, "char&"),
    ("_ZTSRd", 0x9c0979e8233e263d, "double&"),
    ("_ZTSRe", 0x1330f6e9e9fcd96e, "long double&"),
    ("_ZTSRf", 0xc899fc3f8cc4c09c, "float&"),
    ("_ZTSRg", 0x2137cc2f7de9e8b8, "__float128&"),
    ("_ZTSRh", 0xc6322d9732a7c101, "unsigned char&"),
    ("_ZTSRi", 0x920a6d6ed2340446, "int&"),
    ("_ZTSRj", 0x5fa60ad2f1f2aed3, "unsigned int&"),
    ("_ZTSRl", 0x4cf93cedaf1ae0de, "long&"),
    ("_ZTSRm", 0xfc00205ffeed269a, "unsigned long&"),
    ("_ZTSRn", 0xcbccfae00d3c7672, "__int128&"),
    ("_ZTSRo", 0xcddebb7991acc340, "unsigned __int128&"),
    ("_ZTSRs", 0xbe41b1d30c190934, "short&"),
    ("_ZTSRt", 0xdcb042899adc2df2, "unsigned short&"),
    ("_ZTSRv", 0x7347f3fa83f4b6b1, "void&"),
    ("_ZTSRw", 0xe63a0a115301b82c, "wchar_t&"),
    ("_ZTSRx", 0xb3556a3f34f47e87, "long long&"),
    ("_ZTSRy", 0x279706ab2e0cd593, "unsigned long long&"),
    ("_ZTSRz", 0xd0874ed53e53bf59, "...&"),

    ("_ZTSSa", 0xa6b329bb6ad3e84a, "std::allocator"),
    ("_ZTSSb", 0x2793a7538d42eded, "std::basic_string"),
    ("_ZTSSd", 0xadc99c5b078f924f, "std::basic_iostream<char, std::char_traits<char> >"),
    ("_ZTSSi", 0x07d9f6cfd01e6c2f, "std::basic_istream<char, std::char_traits<char> >"),
    ("_ZTSSo", 0x3594d9d23230b396, "std::basic_ostream<char, std::char_traits<char> >"),
    ("_ZTSSs", 0xc04d2a85c2b94a68, "std::basic_string<char, std::char_traits<char>, std::allocator<char> >"),

    ("_ZTSVa", 0xd72b2087914637ed, "signed char volatile"),
    ("_ZTSVb", 0x54f21699f9222d28, "bool volatile"),
    ("_ZTSVc", 0x3ae046e9ac1419d1, "char volatile"),
    ("_ZTSVd", 0x88bc008d482c74c3, "double volatile"),
    ("_ZTSVe", 0x7804789a504172d2, "long double volatile"),
    ("_ZTSVf", 0xec6f86e3ceff093c, "float volatile"),
    ("_ZTSVg", 0x38af2108020d72cc, "__float128 volatile"),
    ("_ZTSVh", 0x3046f5cac80ff62f, "unsigned char volatile"),
    ("_ZTSVi", 0x9e0683be72dd2e4e, "int volatile"),
    ("_ZTSVj", 0x954a28601e9edba8, "unsigned int volatile"),
    ("_ZTSVl", 0x7a0501b467789fd0, "long volatile"),
    ("_ZTSVm", 0xb2e5fcc1520e9e95, "unsigned long volatile"),
    ("_ZTSVn", 0xb1e810b2287e677b, "__int128 volatile"),
    ("_ZTSVo", 0xb89963001dd495a2, "unsigned __int128 volatile"),
    ("_ZTSVs", 0xb3342ef0b0a42bcf, "short volatile"),
    ("_ZTSVt", 0xd32d4fff5f991e6c, "unsigned short volatile"),
    ("_ZTSVv", 0x8df546e2d525c8f7, "void volatile"),
    ("_ZTSVw", 0x35e27c6692a95c1c, "wchar_t volatile"),
    ("_ZTSVx", 0x6af567b54da5e648, "long long volatile"),
    ("_ZTSVy", 0x1ceabbadcf0acb70, "unsigned long long volatile"),
    ("_ZTSVz", 0x6a5473cf4b58c5b7, "... volatile"),

    # Function types: with F..E delimiters
    ("_ZTSFvvE", 0x7e04a0fb7ad8bcd5, "void ()"),
    ("_ZTSFimE", 0x5b25abe30df04fc4, "int (unsigned long)"),
    ("_ZTSFPvmE", 0x561a39225c617dcf, "void* (unsigned long)"),
    ("_ZTSFPvPvPKvmE", 0x718953c4d54cf865, "void* (void*, void const*, unsigned long)"),

    # Function from Linux kernel for struct file_operations::read
    ("_ZTSFlP4filePcmPxE", 0x07ff5a213d37b1a6, "long (file*, char*, unsigned long, long long*)"),
    # Function from Linux kernel for struct file_operations::write
    ("_ZTSFlP4filePKcmPxE", 0x1d7ed092cb04d3f1, "long (file*, char const*, unsigned long, long long*)"),
)


def get_typeid(typeinfo):
    """Compute the CallSiteTypeId from a typeinfo string"""
    return int.from_bytes(hashlib.md5(typeinfo.encode("ascii")).digest()[:8], "little")


def decode_typeinfo(typeinfo):
    """Invoke c++filt to decode a typeinfo"""
    type_string = subprocess.check_output(["c++filt", typeinfo], stdin=subprocess.DEVNULL)
    if not type_string.startswith(b"typeinfo name for "):
        raise ValueError(f"Unexpected c++filt output for {typeinfo!r}: {type_string!r}")
    return type_string[18:].decode("ascii").strip()


def check_known_types():
    """Check some known typeinfo names"""
    has_error = False
    for typeinfo, known_typeid, known_type_string in KNOWN_TYPEINFO_NAMES:
        typeid = get_typeid(typeinfo)
        if typeid != known_typeid:
            print(f"Unexpected typeid for {typeinfo!r}: {typeid:#018x} != {known_typeid:#018x}")
            has_error = True

        type_string = decode_typeinfo(typeinfo)
        if type_string != known_type_string:
            print(f"Unexpected typeid for {typeinfo!r}: {type_string!r} != {known_type_string!r}")
            has_error = True

        print(f"{typeinfo!r} ({typeid:#018x}): {type_string!r}")
    assert not has_error


if __name__ == "__main__":
    if len(sys.argv) == 1:
        check_known_types()
    else:
        for typeinfo in sys.argv[1:]:
            typeid = get_typeid(typeinfo)
            type_string = decode_typeinfo(typeinfo)
            print(f"{typeinfo!r} ({get_typeid(typeinfo):#018x}): {type_string!r}")
