# Notes about x86 EVEX lack of support

Since glibc 2.34, the string-based functions can be optimised using EVEX (Enhanced Vector Extension): <https://en.wikipedia.org/wiki/EVEX_prefix>

> The EVEX coding scheme uses a code prefix consisting of 4 bytes; the first byte is always 62h and derives from an unused opcode of the 32-bit BOUND instruction, which is not supported in 64-bit mode.

## Assembly

For example `strlen` is implemented in [`sysdeps/x86_64/multiarch/strlen-evex.S`](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/multiarch/strlen-evex.S;h=4bf6874b823355196933922a19e5fe59eacc03e8;hb=refs/tags/glibc-2.34) as:

```text
        /* Check the first VEC_SIZE bytes.  Each bit in K0 represents a
           null byte.  */
        VPCMP   $0, (%rdi), %YMMZERO, %k0
        kmovd   %k0, %eax
# ifdef USE_AS_STRNLEN
        /* If length < CHAR_PER_VEC handle special.  */
        cmpq    $CHAR_PER_VEC, %rsi
        jbe     L(first_vec_x0)
# endif
        testl   %eax, %eax
        jz      L(aligned_more)
```

This gets compiled to:

```
00000000001b2220 <__strlen_evex>:
  1b2220:       f3 0f 1e fa             endbr64
  1b2224:       89 f8                   mov    %edi,%eax
  1b2226:       62 a1 fd 00 ef c0       vpxorq %xmm16,%xmm16,%xmm16
  1b222c:       25 ff 0f 00 00          and    $0xfff,%eax
  1b2231:       3d e0 0f 00 00          cmp    $0xfe0,%eax
  1b2236:       0f 87 34 01 00 00       ja     1b2370 <__strlen_evex+0x150>

  1b223c:       62 f3 7d 20 3f 07 00    vpcmpeqb (%rdi),%ymm16,%k0
  1b2243:       c5 fb 93 c0             kmovd  %k0,%eax
  1b2247:       85 c0                   test   %eax,%eax
  1b2249:       74 55                   je     1b22a0 <__strlen_evex+0x80>
```

Intel's documentation (<https://www.felixcloutier.com/x86/pcmpeqb:pcmpeqw:pcmpeqd>) defines:

- Opcode/Instruction: `EVEX.256.66.0F.WIG 74 /r VPCMPEQB k1 {k2}, ymm2, ymm3 /m256`
- CPUID Feature Flag: AVX512VL AVX512BW
- Description: Compare packed bytes in ymm3/m256 and ymm2 for equality and set vector mask k1 to reflect the zero/nonzero status of each element of the result, under writemask.

and (<https://www.felixcloutier.com/x86/kmovw:kmovb:kmovq:kmovd>):

- Opcode/Instruction: `VEX.L0.F2.0F.W0 93 /r KMOVD r32, k1`
- CPUID Feature Flag: AVX512BW
- Description: Move 32 bits mask from k1 to r32.

These instructions come from the AVX-512 extensions (Advanced Vector Extensions, <https://en.wikipedia.org/wiki/AVX-512>) and more precisely:

- AVX-512 Vector Length Extensions (VL) – extends most AVX-512 operations to also operate on XMM (128-bit) and YMM (256-bit) registers
- AVX-512 Byte and Word Instructions (BW) – extends AVX-512 to cover 8-bit and 16-bit integer operations

## Register access

While `k0` and `zmm16` (which includes `ymm16`) are saved by `xsaves`, they are not supported in glibc context structures.
[`sysdeps/unix/sysv/linux/x86/sys/ucontext.h`](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86/sys/ucontext.h;h=e4bf82db6a1d110a1f1d29ac8b44f7bb82e8b7ca;hb=refs/tags/glibc-2.37#l108) defines that the machine context `mcontext_t` uses `fpregset_t fpregs` to target a FPU area defined in `struct _libc_fpstate` with only the 16 XMM registers (`struct _libc_xmmreg _xmm[16];`): the higher bits of the YMM registers are not available, nor the high ZMM registers.
The registers `k0`, `k1`... are also not available.

This makes the logic used by the `recover_segfault` project not applicable: to support EVEX, some logic around `xsave` needs to be implemented and some care needs to be taken into account in the handler to not modify these registers.

Because of this, it was decided to not support systems using EVEX to implement `strlen` and other functions related to strings operations.

## Feature detection

How can EVEX support by glibc can be detected?
The main logic in glibc is in [`sysdeps/x86_64/multiarch/ifunc-evex.h`](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/multiarch/ifunc-evex.h;h=fc391edb8abc7d7fda96af19ed27b29466a61dc7;hb=refs/tags/glibc-2.34): it looks for features AVX2, AVX512VL and AVX512BW.

These features are defined in [`sysdeps/x86/include/cpu-features.h`](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86/include/cpu-features.h;h=28be3e0c0a168d0d68b5d470eb414bfbc1d8def9;hb=refs/tags/glibc-2.34):

- AVX2 is CPUID 7, register EBX, bit 5
- AVX512BW is CPUID 7, register EBX, bit 30
- AVX512VL is CPUID 7, register EBX, bit 31

glibc embeds some detection in [`sysdeps/x86/cpu-features.c`](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86/cpu-features.c;h=645bba63147f6589eb6ae716b7293f42f7e41d9a;hb=refs/tags/glibc-2.34#l761) to add the bit `HWCAP_X86_AVX512_1` to `dl_hwcap`.
This is used by the dynamic linker to search for optimized libraries in `glibc-hwcaps` directories, as described on <https://www.phoronix.com/news/Glibc-2.33-Coming-HWCAPS>.

This is unfortunately not available through `getauxval(AT_HWCAP)` (which gives CPUID 1 register EDX, cf. <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/elf.h?h=v6.2#n240>)) and `getauxval(AT_HWCAP2)` (which only gives bits defined in [`asm/hwcap2.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/uapi/asm/hwcap2.h?h=v6.2)).

There is a way to dynamically disable some CPU features in glibc, given on <https://stackoverflow.com/questions/42451492/disable-avx-optimized-functions-in-glibc-ld-hwcap-mask-etc-ld-so-nohwcap-for>:

```sh
GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX2_Usable,-AVX_Fast_Unaligned_Load
```

This is also documented in a comment in [`sysdeps/x86/cpu-features.c`](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86/cpu-features.c;h=645bba63147f6589eb6ae716b7293f42f7e41d9a;hb=refs/tags/glibc-2.34#l761) and more precisely in [`sysdeps/x86/cpu-tunables.c`](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86/cpu-tunables.c;h=00fe5045eb56eb076d08f55068692bcf1a1cd2c7;hb=refs/tags/glibc-2.34#l92):

```text
The current IFUNC selection is based on microbenchmarks in glibc.
It should give the best performance for most workloads.  But other
choices may have better performance for a particular workload or on
the hardware which wasn't available when the selection was made.
The environment variable:

GLIBC_TUNABLES=glibc.cpu.hwcaps=-xxx,yyy,-zzz,....

can be used to enable CPU/ARCH feature yyy, disable CPU/ARCH feature
yyy and zzz, where the feature name is case-sensitive and has to
match the ones in cpu-features.h.  It can be used by glibc developers
to tune for a new processor or override the IFUNC selection to
improve performance for a particular workload.

NOTE: the IFUNC selection may change over time.  Please check all
multiarch implementations when experimenting.
```

So using `GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512BW,-AVX512VL` should work to prevent glibc from using EVEX implementations... but it does not.
Instead, search for `avx512bw avx512vl` in `/proc/cpuinfo`.
