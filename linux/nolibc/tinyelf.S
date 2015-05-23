/**
 * Tiny ELF file written in pure binary code, exits with code 42
 *
 * Sizes:
 * * ARM, x86: 45 bytes non-respectful, 76 if respectful of ELF specification
 * * x86_64: 112 bytes
 *
 * Documentation:
 * * http://man7.org/linux/man-pages/man5/elf.5.html man 5 elf
 *
 * Inspiration from:
 * * http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
 *   A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux
 * * http://mainisusuallyafunction.blogspot.de/2015/01/151-byte-static-linux-binary-in-rust.html
 * * http://hookrace.net/blog/nim-binary-size/
 */

/* Set to 1 to build an ELF file respectful to the ELF specification */
#ifndef RESPECT_ELF_SPEC
#    define RESPECT_ELF_SPEC 01
#endif

#if defined(__arm__)

#    define USE_ELF32 1
#    define ELF_MACHINE 0x28 /* EM_ARM */
.macro STARTCODE_6BYTES
/* Do not use ".thumb" to avoid an automatic 2-byte alignment */
_thumb_start:
    .short 0x202a   /* mov r0, #0x2a */
    .short 0x2701   /* mov r7, #1 */
    .short 0xdf01   /* svc 1 */
/* Force thumb mode on entry point */
 _start = _thumb_start + 1
.endm

/* 7 bytes, unaligned code */
.macro STARTCODE_7U
    .byte 0
    STARTCODE_6BYTES
.endm
/* 8 bytes, aligned code */
.macro STARTCODE_8A
    STARTCODE_6BYTES
    .byte 0, 0
.endm

#elif defined(__i386__)

#    define USE_ELF32 1
#    define ELF_MACHINE 3 /* EM_386 */
.macro STARTCODE_7U
_start:
    .byte 0xb3, 0x2a    /* mov $0x2a,%bl */
    .byte 0x31, 0xc0    /* xor %eax,%eax */
    .byte 0x40          /* inc %eax */
    .byte 0xcd, 0x80    /* int $0x80 */
.endm
.macro STARTCODE_8A
    STARTCODE_7U
    .byte 0
.endm

#elif defined(__x86_64__)

#    define USE_ELF64 1
#    define ELF_MACHINE 0x3e /* EM_X86_64 */
.macro STARTCODE_8A
_start:
    .byte 0x6a, 0x2a    /* push $0x2a */
    .byte 0x5f          /* pop %rdi */
    .byte 0x6a, 0x3c    /* push $0x3c */
    .byte 0x58          /* pop %eax */
    .byte 0x0f, 0x05    /* syscall */
.endm

#else
#    error Unsupported architecture
#endif


    .data
file_start:

#if defined(USE_ELF32) && RESPECT_ELF_SPEC

/* 32-bit ELF file respectful of the specification */

ehdr:
    .int 0x464c457f     /* Elf32_Ehdr.e_ident[EI_MAG0..3] = ELF magic */
    .byte 1             /* Elf32_Ehdr.e_ident[EI_CLASS] = ELFCLASS32 */
    .byte 1             /* Elf32_Ehdr.e_ident[EI_DATA] = ELFDATA2LSB */
    .byte 1             /* Elf32_Ehdr.e_ident[EI_VERSION] = 1 */
    .byte 0             /* Elf32_Ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE */
    .byte 1             /* Elf32_Ehdr.e_ident[EI_ABIVERSION] = 1 */
    STARTCODE_7U        /* Elf32_Ehdr padding (7 bytes) */
    .short 3            /* Elf32_Ehdr.e_type = ET_DYN for PIE executable */
    .short ELF_MACHINE  /* Elf32_Ehdr.e_machine = EM_... */
    .int 1              /* Elf32_Ehdr.e_version = 1 */
    .int _start - ehdr  /* Elf32_Ehdr.e_entry */
    .int phdr - ehdr    /* Elf32_Ehdr.e_phoff */
    .int 0              /* Elf32_Ehdr.e_shoff */
    .int 0              /* Elf32_Ehdr.e_flags */
    .short ehdr_size    /* Elf32_Ehdr.e_ehsize */
    .short phdr_size    /* Elf32_Ehdr.e_phentsize */
phdr:
    .short 1            /* Elf32_Ehdr.e_phnum = 1,
                         *      Elf32_Phdr.p_type = PT_LOAD */
    .short 0            /* Elf32_Ehdr.e_shentsize */
    .short 0            /* Elf32_Ehdr.e_shnum,
                         *      Elf32_Phdr.p_offset = 0 */
    .short 0            /* Elf32_Ehdr.e_shstrndx */
ehdr_size = . - ehdr    /* -- end of Elf32_Ehdr -- */
    .int 0              /*      Elf32_Phdr.p_vaddr */
    .int 0              /*      Elf32_Phdr.p_paddr */
    .int file_size      /*      Elf32_Phdr.p_filesz */
    .int file_size      /*      Elf32_Phdr.p_memsz */
    .int 5              /*      Elf32_Phdr.p_flags = PF_R | PF_X */
    .int 0x1000         /*      Elf32_Phdr.p_align = 0x1000 */
phdr_size = . - phdr    /*      -- end of Elf32_Phdr -- */

#elif defined(USE_ELF32)

/* 32-bit ELF file non-respectful of the spec */

ehdr:
    .int 0x464c457f     /* Elf32_Ehdr.e_ident[EI_MAG0..3] = ELF magic */
phdr:
    .byte 1             /* Elf32_Ehdr.e_ident[EI_CLASS] = ELFCLASS32,
                         *      Elf32_Phdr.p_type = PT_LOAD */
    .byte 0             /* Elf32_Ehdr.e_ident[EI_DATA] = 0 (not ELFDATA2LSB=1) */
    .byte 0             /* Elf32_Ehdr.e_ident[EI_VERSION] = 0 (not 1) */
    .byte 0             /* Elf32_Ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE */
    .byte 0             /* Elf32_Ehdr.e_ident[EI_ABIVERSION] = 0,
                         *      Elf32_Phdr.p_offset = 0 */
    .byte 0, 0, 0       /* Elf32_Ehdr.e_ident padding (7 bytes) */
    .int 0              /*      Elf32_Phdr.p_vaddr = 0 */
    .short 3            /* Elf32_Ehdr.e_type = ET_DYN for PIE executable,
                         *      Elf32_Phdr.p_paddr (ignored) */
    .short ELF_MACHINE  /* Elf32_Ehdr.e_machine = EM_... */
    .int _start - ehdr  /* Elf32_Ehdr.e_version (not 1),
                         *      Elf32_Phdr.p_filesz */
    .int _start - ehdr  /* Elf32_Ehdr.e_entry,
                         *      Elf32_Phdr.p_memsz */
    .int 4              /* Elf32_Ehdr.e_phoff,
                         *      Elf32_Phdr.p_flags = PF_R (not PF_R|PF_X=5) */
    STARTCODE_8A        /* Elf32_Ehdr.e_shoff,
                         *      Elf32_Phdr.p_align
                         * Elf32_Ehdr.e_flags */
phdr_size = . - phdr - 4    /*  -- end of Elf32_Phdr -- */
    .short ehdr_size    /* Elf32_Ehdr.e_ehsize */
    .short phdr_size    /* Elf32_Ehdr.e_phentsize */
    .byte 1             /* Elf32_Ehdr.e_phnum = 1 */
                        /* Elf32_Ehdr.e_shentsize = 0 */
                        /* Elf32_Ehdr.e_shnum = 0 */
                        /* Elf32_Ehdr.e_shstrndx */
ehdr_size = . - ehdr    /* -- end of Elf32_Ehdr -- */

#elif defined(USE_ELF64)

ehdr:
    .int 0x464c457f     /* Elf64_Ehdr.e_ident[EI_MAG0..3] = ELF magic */
    .byte 2             /* Elf64_Ehdr.e_ident[EI_CLASS] = ELFCLASS64 */
    .byte 1             /* Elf64_Ehdr.e_ident[EI_DATA] = ELFDATA2LSB */
    .byte 1             /* Elf64_Ehdr.e_ident[EI_VERSION] = 1 */
    .byte 0             /* Elf64_Ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE */
    STARTCODE_8A        /* Elf64_Ehdr.e_ident[EI_ABIVERSION] (not 0) */
                        /* Elf64_Ehdr padding (7 bytes) */
    .short 3            /* Elf64_Ehdr.e_type = ET_DYN for PIE executable */
    .short ELF_MACHINE  /* Elf64_Ehdr.e_machine = EM_... */
    .int 1              /* Elf64_Ehdr.e_version = 1 */
    .quad _start - ehdr /* Elf64_Ehdr.e_entry */
    .quad phdr - ehdr   /* Elf64_Ehdr.e_phoff */
    .quad 0             /* Elf64_Ehdr.e_shoff */
    .int 0              /* Elf64_Ehdr.e_flags */
    .short ehdr_size    /* Elf64_Ehdr.e_ehsize */
    .short phdr_size    /* Elf64_Ehdr.e_phentsize */
phdr:
    .short 1            /* Elf64_Ehdr.e_phnum = 1,
                         *      Elf64_Phdr.p_type = PT_LOAD */
    .short 0            /* Elf64_Ehdr.e_shentsize */
    .short 5            /* Elf64_Ehdr.e_shnum,
                         *      Elf64_Phdr.p_flags = PF_R | PF_X */
    .short 0            /* Elf64_Ehdr.e_shstrndx */
ehdr_size = . - ehdr    /* -- end of Elf64_Ehdr -- */
    .quad 0             /*      Elf64_Phdr.p_offset */
    .quad 0             /*      Elf64_Phdr.p_vaddr */
    .quad 0             /*      Elf64_Phdr.p_paddr */
    .quad file_size     /*      Elf64_Phdr.p_filesz */
    .quad file_size     /*      Elf64_Phdr.p_memsz */
    .quad 0x1000        /*      Elf64_Phdr.p_align = 0x1000 */
phdr_size = . - phdr    /*      -- end of Elf64_Phdr -- */

#else
#    error BUG! Neither USE_ELF32 nor USE_ELF64 is defined
#endif

file_size = . - file_start
