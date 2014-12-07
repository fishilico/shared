/**
 * This files defines a few things which are needed when analyzing Linux with
 * Frama-C and is expected to be used as a force-included header.
 * It defines some structures which are kept abstract in UML allnoconfig, and
 * macro definitions to make Frama-C work.
 */

/* When a .s needs to be generated from a .c, like arch/x86/um/user-offsets.c,
 * KCPPFLAGS are not applied and hence __FRAMAC__ is not defined.
 * Use #ifdef to keep such files as usual.
 */
#ifdef __FRAMAC__

/* Some abstract types which are not defined */
struct dma_coherent_mem { char dummy; };
struct dn_dev { char dummy; };
struct forwarding_accel_ops { char dummy; };
struct garp_port { char dummy; };
struct in_device { char dummy; };
struct iommu_group { char dummy; };
struct iommu_ops { char dummy; };
struct ipv4_devconf { char dummy; };
struct kernfs_iattrs { char dummy; };
struct mem_cgroup { char dummy; };
struct module { char dummy; };
struct mrp_port { char dummy; };
struct net_generic { char dummy; };
struct phy_device { char dummy; };
struct prot_inuse { char dummy; };
struct Qdisc { char dummy; };
struct tcpm_hash_bucket { char dummy; };
struct wireless_dev { char dummy; };

/* Frama-C complains about integer types being redefined:
 *
 *   /usr/lib/gcc/x86_64-unknown-linux-gnu/4.9.0/include/stdint-gcc.h:34:
 *   [kernel] user error: redefinition of 'int8_t' in the same scope.
 *   Previous declaration was at /usr/include/sys/types.h:194
 *
 * Fix this by forcing __INT*_TYPE__ to be undefined
 */
#undef __INT8_TYPE__
#undef __INT16_TYPE__
#undef __INT32_TYPE__
#undef __INT64_TYPE__
#undef __INTPTR_TYPE__

/* Don't redefine some types in Frama-C standard library */
#define __FC_DEFINE_SIZE_T
#define __FC_STDDEF

/* Frama-C hasn't got __builtin_return_address so fake it with "garbage" */
#define __builtin_return_address(level) ((void*)(0x9e70000 + 16 * (level)))

/* Fake sp and bp registers */
#define FRAMAC_REG_SP ((void*)0x57ac0000)
#define FRAMAC_REG_BP 0xba5e0000UL

/* Define a dummy __builtin_extract_return_addr
 * GCC documentation: https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html
 */
#define __builtin_extract_return_addr(ptr) (ptr)

/* Frama-C doesn't understand __attribute__((__aligned__(...))), so remove these definitions */
#define ____cacheline_aligned
#define __cacheline_aligned
#define ____cacheline_internodealigned_in_smp

#endif
