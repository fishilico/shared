/**
 * Read vDSO file
 *
 * To dump the content of auxv, set LD_SHOW_AUXV environment variable to 1
 *
 * Documentation:
 * * http://man7.org/linux/man-pages/man7/vdso.7.html
 * * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/vDSO
 */
#include <assert.h>
#include <elf.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#if defined __x86_64__
#define DEFINE_ELF_STRUCT(name) typedef Elf64_##name Elf_##name
#define ELF_ST_BIND(val) ELF64_ST_BIND(val)
#define ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#define ELF_ST_INFO(bind, type) ELF64_ST_INFO((bind), (type))
#elif defined  __i386__ || defined __arm__
#define DEFINE_ELF_STRUCT(name) typedef Elf32_##name Elf_##name
#define ELF_ST_BIND(val) ELF32_ST_BIND(val)
#define ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#define ELF_ST_INFO(bind, type) ELF32_ST_INFO ((bind), (type))
#else
#error Unsupported architecture
#endif
DEFINE_ELF_STRUCT(auxv_t);
DEFINE_ELF_STRUCT(Dyn);
DEFINE_ELF_STRUCT(Ehdr);
DEFINE_ELF_STRUCT(Phdr);
DEFINE_ELF_STRUCT(Sym);
DEFINE_ELF_STRUCT(Verdef);
DEFINE_ELF_STRUCT(Verdaux);
DEFINE_ELF_STRUCT(Versym);
DEFINE_ELF_STRUCT(Word);

/**
 * Implement getauxval for old systems without sys/auxv.h
 *
 * In Linux ABI, the initial stack contains:
 * * argc
 * * char* argv[0]...argv[argc-1]
 * * NULL
 * * envp[0]...
 * * NULL
 * * Elf_auxv_t auxv[0]...{.a_type = AT_NULL}
 */
static unsigned long getauxval_from_args(unsigned long type, int argc, char **argv)
{
    void **stack;
    Elf_auxv_t *auxv;
    int i;

    assert(argc >= 0 && argv[argc] == NULL);
    stack = (void**)&argv[argc + 1];
    /* Skip environment variables */
    while (*stack) {
        stack++;
    }
    auxv = (Elf_auxv_t*)(stack + 1);
    for (i = 0; auxv[i].a_type != AT_NULL; i++) {
        if (auxv[i].a_type == type) {
            return auxv[i].a_un.a_val;
        }
    }
    return 0L;
}

int main(int argc, char **argv)
{
    size_t i;
    uintptr_t vdso_base = 0;
    uintptr_t vdso_load_offset = 0;
    const Elf_Ehdr *vdso_hdr = NULL;
    const Elf_Phdr *vdso_pt = NULL;
    const Elf_Dyn *vdso_dyn = NULL;
    const Elf_Word *vdso_hash = NULL;
    const Elf_Sym *vdso_symtab = NULL, *sym;
    const char *vdso_symstrings = NULL;
    const Elf_Versym *vdso_versym = NULL;
    const Elf_Verdef *vdso_verdef = NULL;
    const Elf_Word *vdso_bucket, *vdso_chain;
    Elf_Word vdso_nbucket, vdso_nchain;

    /* Retrieve vDSO address from the auxiliary vector */
    vdso_base = (uintptr_t)getauxval_from_args(AT_SYSINFO_EHDR, argc, argv);
    if (!vdso_base) {
        fprintf(stderr, "SYSINFO_EHDR not found in auxv\n");
        return 1;
    }
    printf("vDSO header found @0x%"PRIxPTR"\n", vdso_base);

    vdso_hdr = (Elf_Ehdr*)vdso_base;
    vdso_pt = (Elf_Phdr*)(vdso_base + vdso_hdr->e_phoff);
    for (i = 0; i < vdso_hdr->e_phnum; i++) {
        if (vdso_pt[i].p_type == PT_LOAD && !vdso_load_offset) {
            vdso_load_offset = vdso_base + vdso_pt[i].p_offset - vdso_pt[i].p_vaddr;
        } else if (vdso_pt[i].p_type == PT_DYNAMIC) {
            vdso_dyn = (Elf_Dyn*)(vdso_base + vdso_pt[i].p_offset);
        }
    }
    if (!vdso_load_offset || !vdso_dyn) {
        fprintf(stderr, "Unable to find PT_LOAD and PT_DYNAMIC is vDSO header\n");
        return 1;
    }
    printf("* EHDR = %p\n", (void*)vdso_hdr);
    printf("* PHDR = %p\n", (void*)vdso_pt);
    printf("* PT_LOAD = %p\n", (void*)vdso_load_offset);
    printf("* PT_DYNAMIC = %p\n", (void*)vdso_dyn);

    /* Gather information from PT_DYNAMIC header */
    for (i = 0; vdso_dyn[i].d_tag != DT_NULL; i++) {
        const void *ptr = (void*)(vdso_load_offset + vdso_dyn[i].d_un.d_ptr);
        switch (vdso_dyn[i].d_tag) {
            case DT_STRTAB:
                vdso_symstrings = ptr;
                break;
            case DT_SYMTAB:
                vdso_symtab = ptr;
                break;
            case DT_HASH:
                vdso_hash = ptr;
                break;
            case DT_VERSYM:
                vdso_versym = ptr;
                break;
            case DT_VERDEF:
                vdso_verdef = ptr;
                break;
        }
    }
    if (!vdso_symstrings || !vdso_symtab || !vdso_hash) {
        fprintf(stderr, "Unable to find mandatory fields in PT_DNYAMIC header\n");
        return 1;
    }
    if (!vdso_verdef) {
        vdso_versym = NULL;
    }
    vdso_nbucket = vdso_hash[0];
    vdso_nchain = vdso_hash[1];
    vdso_bucket = &vdso_hash[2];
    vdso_chain = &vdso_hash[2 + vdso_nbucket];
    /* Use hashtables */
    (void)vdso_bucket;
    (void)vdso_chain;

    /* List symbols */
    printf("\nExported functions:\n");
    for (i = 0; i < vdso_nchain; i++) {
        const char *bindstr = NULL;
        const char *verstr = NULL;
        sym = &vdso_symtab[i];
        if (ELF_ST_TYPE(sym->st_info) != STT_FUNC || sym->st_shndx == SHN_UNDEF) {
            continue;
        }
        if (ELF_ST_BIND(sym->st_info) == STB_GLOBAL) {
            bindstr = "global";
        } else if (ELF_ST_BIND(sym->st_info) == STB_WEAK) {
            bindstr = "weak";
        } else if (ELF_ST_BIND(sym->st_info) == STB_LOCAL) {
            bindstr = "local";
        } else {
            continue;
        }
        if (vdso_versym) {
            Elf_Versym ver = vdso_versym[i] & 0x7fff;
            const Elf_Verdef *def = vdso_verdef;
            while (1) {
                if ((def->vd_flags & VER_FLG_BASE) == 0 && (def->vd_ndx & 0x7fff) == ver) {
                    Elf_Verdaux *aux = (Elf_Verdaux*)((char *)def + def->vd_aux);
                    verstr = &vdso_symstrings[aux->vda_name];
                    break;
                }
                if (!def->vd_next) {
                    break;
                }
                def = (Elf_Verdef*)((uint8_t*)def + def->vd_next);
            }
        }
        printf("* %s = %p (%s",
            vdso_symstrings + sym->st_name, (void*)(vdso_load_offset + sym->st_value), bindstr);
        if (verstr) {
            printf(", %s", verstr);
        }
        printf(")\n");
    }
    return 0;
}
