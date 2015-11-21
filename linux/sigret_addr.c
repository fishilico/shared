/**
 * Retrieve the address which is used to return from a signal handler and
 * find out what it is (function in an ELF file, vdso part, etc.)
 *
 * To get the ASM code of the signal-return handle, it is possible to use gdb
 * on this program.
 *
 * Documentation:
 * * http://man7.org/linux/man-pages/man2/sigreturn.2.html "man 2 sigreturn"
 * * http://git.musl-libc.org/cgit/musl/tree/src/signal/i386/restore.s?id=v1.1.6
 *   musl implementation of the signal restorer for i386
 * * https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/i386/sigaction.c;hb=b8079dd0d360648e4e8de48656c5c38972621072#l89
 *   glibc implementation of the signal restorer for i386
 *
 * Results when using a simple signal handler:
 * * arm, glibc: __default_sa_restorer (syscall 119 = sigreturn)
 * * x86_32, vdso: __kernel_sigreturn (syscall 119 = sigreturn)
 * * x86_64, glibc: __restore_rt (syscall 15 = rt_sigreturn)
 *
 * Results when using sigaction with SA_INFO ("rt_sigaction"):
 * * arm, glibc: __default_rt_sa_restorer (syscall 173 = rt_sigreturn)
 * * x86_32, vdso: __kernel_rt_sigreturn (syscall 173 = rt_sigreturn)
 * * x86_64, glibc: __restore_rt (syscall 15 = rt_sigreturn), same as simple
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for sigaction */
#endif

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__x86_64__)
#    define DEFINE_ELF_STRUCT(name) typedef Elf64_##name Elf_##name
#    define ELF_ST_BIND(val) ELF64_ST_BIND(val)
#    define ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#    define ELF_ST_INFO(bind, type) ELF64_ST_INFO((bind), (type))
#    define ELFCLASS_CURRENT ELFCLASS64
#elif defined(__i386__) || defined(__arm__)
#    define DEFINE_ELF_STRUCT(name) typedef Elf32_##name Elf_##name
#    define ELF_ST_BIND(val) ELF32_ST_BIND(val)
#    define ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#    define ELF_ST_INFO(bind, type) ELF32_ST_INFO ((bind), (type))
#    define ELFCLASS_CURRENT ELFCLASS32
#else
#    error Unsupported architecture
#endif
DEFINE_ELF_STRUCT(auxv_t);
DEFINE_ELF_STRUCT(Dyn);
DEFINE_ELF_STRUCT(Ehdr);
DEFINE_ELF_STRUCT(Phdr);
DEFINE_ELF_STRUCT(Shdr);
DEFINE_ELF_STRUCT(Sym);
DEFINE_ELF_STRUCT(Verdef);
DEFINE_ELF_STRUCT(Verdaux);
DEFINE_ELF_STRUCT(Versym);
DEFINE_ELF_STRUCT(Word);

static const void * volatile sigret_address;

static void sig_user(
    int signum __attribute__ ((unused)),
    siginfo_t *si  __attribute__ ((unused)),
    void *unused  __attribute__ ((unused)))
{
    sigret_address = __builtin_return_address(0);
}

/**
 * Identify the code which lies at the return address of the signal handler
 */
static void identify_sigret_code(const void *address)
{
    uint32_t i;
    const uint8_t *addr = (const uint8_t *)address;

#if defined(__arm__)
    if ((uintptr_t)addr & 1) {
        /* Thumb code */
        addr -= 1;
        if (!memcmp(addr, "\x4f\xf0", 2) && !memcmp(addr + 3, "\x07\x00\xdf", 3)) {
            /* mov.w r7, #... ; svc 0 */
            printf("... code: syscall_svc0(%u)\n", addr[2]);
            return;
        }
    } else {
        /* ARM code */
        if (!memcmp(addr + 1, "\x70\xa0\xe3\x00\x00\x00\xef", 7)) {
            /* mov r7, #... ; svc 0 */
            printf("... code: syscall_svc0(%u)\n", addr[0]);
            return;
        }
    }
#elif defined(__i386__)
    if (addr[0] == 0xb8 && !memcmp(addr + 5, "\xcd\x80", 2)) {
        /* mov $..., %eax ; int $0x80 */
        memcpy(&i, addr + 1, 4);
        printf("... code: syscall_int80(%u)\n", i);
        return;
    }
    if (!memcmp(addr, "\x58\xb8", 2) && !memcmp(addr + 6, "\xcd\x80", 2)) {
        /* pop %eax ; mov $..., %eax ; int $0x80 */
        memcpy(&i, addr + 2, 4);
        printf("... code: pop %%eax; syscall_int80(%u)\n", i);
        return;
    }
#elif defined(__x86_64__)
    if (!memcmp(addr, "\x48\xc7\xc0", 3) && !memcmp(addr + 7, "\x0f\x05", 2)) {
        /* mov $..., %rax ; syscall */
        memcpy(&i, addr + 3, 4);
        printf("... code: syscall(%u)\n", i);
        return;
    }
#else
#    warning Unsupported architecture
#endif
    printf("... unknown code. Here are some bytes:");
    for (i = 0; i < 8; i++) {
        printf(" %02x", addr[i]);
    }
    printf("\n");
}

static int get_symbol_name_elf(uintptr_t elf_base, const void *addr, int is_file)
{
    size_t i;
    const Elf_Shdr *sect_hdr;
    size_t symtab_length = 0, dynsymtab_length = 0;
    const Elf_Ehdr *elf_hdr = (Elf_Ehdr *)elf_base;
    const Elf_Phdr *prog_hdr;
    const Elf_Dyn *dyn = NULL;
    const Elf_Sym *symtab = NULL, *dynsymtab = NULL;
    const char *symstrings = NULL;
    Elf_Word nchain = 0;
    uintptr_t elf_load_offset = 0;

    /* In a file, find section header and retrieve the symbol table */
    if (is_file && elf_hdr->e_shoff && elf_hdr->e_shnum) {
        sect_hdr = (Elf_Shdr *)(elf_base + elf_hdr->e_shoff);
        for (i = 0; i < elf_hdr->e_shnum; i++) {
            if (sect_hdr[i].sh_type == SHT_SYMTAB) {
                symtab = (Elf_Sym *)(elf_base + sect_hdr[i].sh_offset);
                symtab_length = sect_hdr[i].sh_size / sizeof(Elf_Sym);
            } else if (sect_hdr[i].sh_type == SHT_STRTAB) {
                symstrings = (char *)(elf_base + sect_hdr[i].sh_offset);
            } else if (sect_hdr[i].sh_type == SHT_DYNSYM) {
                /* Grab a pointer and size of .dynsym section */
                dynsymtab = (Elf_Sym *)(elf_base + sect_hdr[i].sh_offset);
                dynsymtab_length = sect_hdr[i].sh_size / sizeof(Elf_Sym);
            }
        }
        if (symtab_length && symstrings) {
            for (i = 0; i < symtab_length; i++) {
                const Elf_Sym *sym = &symtab[i];
                if (ELF_ST_TYPE(sym->st_info) != STT_FUNC || sym->st_shndx == SHN_UNDEF) {
                    continue;
                }
                if ((void *)(uintptr_t)(elf_base + sym->st_value) == addr) {
                    printf("ELF symbol: %s\n", symstrings + sym->st_name);
                    return 0;
                }
            }
        }
        symtab = NULL;
        symstrings = NULL;
    }

    /* Find program header and retrieve the load offset and dynamic section */
    prog_hdr = (Elf_Phdr *)(elf_base + elf_hdr->e_phoff);
    for (i = 0; i < elf_hdr->e_phnum; i++) {
        if (prog_hdr[i].p_type == PT_LOAD && !elf_load_offset) {
            elf_load_offset = elf_base + prog_hdr[i].p_offset - prog_hdr[i].p_vaddr;
        } else if (prog_hdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf_Dyn *)(elf_base + prog_hdr[i].p_offset);
        }
    }
    if (!elf_load_offset || !dyn) {
        fprintf(stderr, "Unable to find PT_LOAD and PT_DYNAMIC in ELF header\n");
        return 1;
    }

    /* Gather information from PT_DYNAMIC header */
    for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
        const void *ptr = (void *)(elf_load_offset + dyn[i].d_un.d_ptr);
        switch (dyn[i].d_tag) {
            case DT_STRTAB:
                symstrings = ptr;
                break;
            case DT_SYMTAB:
                symtab = ptr;
                break;
            case DT_HASH:
                nchain = ((const Elf_Word *)ptr)[1];
                break;
        }
    }

    /* It is possible that PT_DYNAMIC header does not contain a HASH entry
     * Try to grab the number of symbols from the size of SHT_DYNSYM section
     */
    if (!nchain && dynsymtab_length) {
        nchain = dynsymtab_length;
    }

    if (dynsymtab && symtab && dynsymtab != symtab) {
        fprintf(stderr,
                "Section and dynamic headers disagree on the offset of dynamic symbols table: %p != %p\n",
                (const void *)dynsymtab, (const void *)symtab);
        return 1;
    }
    if (dynsymtab_length && nchain != dynsymtab_length) {
        fprintf(stderr,
                "Section and dynamic headers disagree on the length of dynamic symbols table: %lu != %lu\n",
                (unsigned long)dynsymtab_length, (unsigned long)nchain);
        return 1;
    }

    if (!symstrings || !symtab || !nchain) {
        fprintf(stderr, "Unable to find mandatory fields in PT_DYNAMIC header\n");
        return 1;
    }
    for (i = 0; i < nchain; i++) {
        const Elf_Sym *sym = &symtab[i];
        if (ELF_ST_TYPE(sym->st_info) != STT_FUNC || sym->st_shndx == SHN_UNDEF) {
            continue;
        }
        if ((void *)(uintptr_t)(elf_load_offset + sym->st_value) == addr) {
            printf("ELF dynamic symbol: %s\n", symstrings + sym->st_name);
            return 0;
        }
    }
    printf("Unknown symbol.\n");
    return 0;
}

static int describe_address(const void *address)
{
    FILE *fmaps;
    char line[4096], *endchar = NULL;
    const char *name = NULL;
    unsigned long start = 0, end = 0;
    const uint8_t *elf_ident;
    int fd_mapped, ret;
    void *mfile;
    struct stat st;
    size_t offset, file_size;

    /* Find out where this address is using /proc/self/maps */
    fmaps = fopen("/proc/self/maps", "r");
    if (!fmaps) {
        perror("fopen(/proc/self/maps)");
        return 1;
    }
    while (!feof(fmaps)) {
        if (!fgets(line, sizeof(line), fmaps)) {
            if (!feof(fmaps)) {
                perror("fgets");
            }
            break;
        }

        /* Decode the current memory interval */
        start = strtoul(line, &endchar, 16);
        if (!endchar || *endchar != '-') {
            fprintf(stderr, "Unable to read the start of line: %.42s\n", line);
            continue;
        }
        end = strtoul(endchar + 1, &endchar, 16);
        if (!endchar || *endchar != ' ') {
            fprintf(stderr, "Unable to read the interval end of line: %.42s\n", line);
            continue;
        }
        if (start <= (uintptr_t)sigret_address && (uintptr_t)sigret_address < end) {
            /* Get the name of the mapping */
            endchar = strchr(endchar + 1, ' ');
            if (endchar) {
                endchar = strchr(endchar + 1, ' ');
            }
            if (endchar) {
                endchar = strchr(endchar + 1, ' ');
            }
            if (endchar) {
                endchar = strchr(endchar + 1, ' ');
            }
            if (endchar) {
                while (*(++endchar) == ' ') {
                }
                name = endchar;
                endchar = strchr(endchar, '\n');
                if (endchar) {
                    *endchar = '\0';
                }
            }
            break;
        }
    }
    fclose(fmaps);
    if (!start || !end) {
        return 1;
    }
    offset = ((uintptr_t)address) - start;
    printf("Memory range %lx..%lx is %s\n", start, end, name);
    printf("... offset %#lx\n", (unsigned long)offset);

    /* Find usual templates of code */
    identify_sigret_code(address);

    /* If the memory is a mmap-ed file, mmap it again */
    if (name[0] == '/') {
        fd_mapped = open(name, O_RDONLY);
        if (fd_mapped == -1) {
            perror("open");
            return 1;
        }
        if (fstat(fd_mapped, &st) == -1) {
            perror("fstat");
            close(fd_mapped);
            return 1;
        }
        file_size = (size_t)st.st_size;
        mfile = mmap(NULL, file_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd_mapped, 0);
        if (mfile == MAP_FAILED) {
            perror("mmap");
            close(fd_mapped);
            return 1;
        }
        close(fd_mapped);

        elf_ident = (const uint8_t *)mfile;
        if (memcmp(elf_ident, "\177ELF", 4)) {
            fprintf(stderr, "Error: not an ELF file\n");
            munmap(mfile, file_size);
            return 1;
        }
        if (elf_ident[4] != ELFCLASS_CURRENT) {
            fprintf(stderr, "Error: unknown ELF class 0x%02x\n", elf_ident[4]);
            munmap(mfile, file_size);
            return 1;
        }
        ret = get_symbol_name_elf((uintptr_t)mfile, elf_ident + offset, 1);
        munmap(mfile, file_size);
        return ret;
    }

    /* Resolve symbol if it is an ELF file */
    elf_ident = (const uint8_t *)start;
    if (!memcmp(elf_ident, "\177ELF", 4)) {
        if (elf_ident[4] == ELFCLASS_CURRENT) {
            return get_symbol_name_elf(start, address, 0);
        } else {
            fprintf(stderr, "Error: unknown ELF class 0x%02x\n", elf_ident[4]);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    struct sigaction sa;
    int ret;
    const void *sigret_address_simple;

    /* Use SIGUSR1 to get the return address */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sig_user;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }
    raise(SIGUSR1);

    if (!sigret_address) {
        fprintf(stderr, "Unable to capture the signal handler return address\n");
        return 1;
    }

    printf("Signal handler returned to: %p\n", sigret_address);

    ret = describe_address(sigret_address);
    if (ret) {
        return ret;
    }

    printf("\n");

    /* Again, with SA_INFO so that libc uses rt_sigaction */
    sigret_address_simple = sigret_address;
    sigret_address = NULL;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sig_user;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }
    raise(SIGUSR1);
    if (!sigret_address) {
        fprintf(stderr, "Unable to capture the signal handler return address\n");
        return 1;
    }
    printf("Signal handler with siginfo returned to: %p\n", sigret_address);
    if (sigret_address_simple == sigret_address) {
        printf("... same address\n");
        return 0;
    }
    return describe_address(sigret_address);
}
