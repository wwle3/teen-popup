typedef unsigned long size_t;
typedef unsigned long uintptr_t;

#define NULL ((void *) 0)
#define AT_FDCWD (-100)
#define MAPS_FD 9

extern void *dlopen(const char *filename, int flags);
extern void *dlsym(void *handle, const char *symbol);
extern void *malloc(size_t size);
extern void free(void *ptr);
extern void *memcpy(void *dst, const void *src, size_t n);
extern size_t strlen(const char *s);
typedef unsigned long pthread_t;
extern int pthread_create(pthread_t *thread, const void *attr, void *(*start)(void *), void *arg);

#define RTLD_NOW 2

typedef int (*log_fn)(int, const char *, const char *, ...);
static log_fn log_print;

static int strstr_local(const char *hay, const char *needle);

static void nlog(const char *msg) {
    if (log_print != NULL) {
        log_print(4, "ElinTeenPopup", "%s", msg);
    }
}

static int raw4(long number, long a0, long a1, long a2, long a3) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return (int) x0;
}

static int contains_ci(const char *line, size_t n, const char *key) {
    size_t k = strlen(key);
    size_t i;
    if (k == 0 || n < k) {
        return 0;
    }
    for (i = 0; i + k <= n; i++) {
        size_t j;
        for (j = 0; j < k; j++) {
            unsigned char a = (unsigned char) line[i + j];
            unsigned char b = (unsigned char) key[j];
            if (a >= 'A' && a <= 'Z') {
                a = (unsigned char) (a + 32);
            }
            if (b >= 'A' && b <= 'Z') {
                b = (unsigned char) (b + 32);
            }
            if (a != b) {
                break;
            }
        }
        if (j == k) {
            return 1;
        }
    }
    return 0;
}

static int line_hidden(const char *line, size_t n) {
    static const char *keys[] = {
            "lsposed", "lsplant", "lspd", "libxposed", "xposed", "riru", "zygisk",
            "edxp", "sandhook", "frida", "magisk", "teenpopup", "libteenhide", "/data/adb/", NULL
    };
    int i;
    for (i = 0; keys[i] != NULL; i++) {
        if (contains_ci(line, n, keys[i])) {
            return 1;
        }
    }
    return 0;
}

static int read_maps(char *buf, size_t cap, size_t *out_len) {
    int fd = raw4(56, AT_FDCWD, (long) "/proc/self/maps", 0, 0);
    size_t got = 0;
    if (fd < 0) {
        return 0;
    }
    while (got + 4096 < cap) {
        int n = raw4(63, fd, (long) (buf + got), 4096, 0);
        if (n <= 0) {
            break;
        }
        got += (size_t) n;
    }
    raw4(57, fd, 0, 0, 0);
    *out_len = got;
    return 1;
}

static void refresh_maps_fd(void) {
    size_t cap = 1024u * 1024u;
    char *buf = (char *) malloc(cap);
    char *out = (char *) malloc(cap);
    size_t got = 0;
    size_t out_len = 0;
    char *cursor;
    int memfd;
    int duped;
    if (buf == NULL || out == NULL || !read_maps(buf, cap, &got)) {
        free(buf);
        free(out);
        nlog("maps snapshot failed");
        return;
    }
    cursor = buf;
    while (cursor < buf + got && out_len + 1 < cap) {
        size_t remain = (size_t) (buf + got - cursor);
        size_t k;
        size_t line_len = remain;
        for (k = 0; k < remain; k++) {
            if (cursor[k] == '\n') {
                line_len = k;
                break;
            }
        }
        if (!line_hidden(cursor, line_len)) {
            memcpy(out + out_len, cursor, line_len);
            out_len += line_len;
            if (k < remain && out_len + 1 < cap) {
                out[out_len++] = '\n';
            }
        }
        if (k >= remain) {
            break;
        }
        cursor += k + 1;
    }
    memfd = raw4(279, (long) "maps", 0, 0, 0);
    if (memfd >= 0) {
        size_t wrote = 0;
        while (wrote < out_len) {
            int n = raw4(64, memfd, (long) (out + wrote), (long) (out_len - wrote), 0);
            if (n <= 0) {
                break;
            }
            wrote += (size_t) n;
        }
        raw4(62, memfd, 0, 0, 0);
        duped = raw4(24, memfd, MAPS_FD, 0, 0);
        if (memfd != MAPS_FD) {
            raw4(57, memfd, 0, 0, 0);
        }
        if (duped == MAPS_FD) {
            nlog("maps alias ready");
        } else {
            nlog("maps dup failed");
        }
    }
    free(buf);
    free(out);
}

static void clear_icache(void *addr, size_t n) {
    uintptr_t p = (uintptr_t) addr & ~63ull;
    uintptr_t end = (uintptr_t) addr + n;
    uintptr_t q;
    for (q = p; q < end; q += 64) {
        __asm__ volatile("dc cvau, %0" ::"r"(q) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (q = p; q < end; q += 64) {
        __asm__ volatile("ic ivau, %0" ::"r"(q) : "memory");
    }
    __asm__ volatile("dsb ish\n isb" ::: "memory");
}

static int poke(void *addr, const void *bytes, size_t n) {
    uintptr_t page = (uintptr_t) addr & ~4095ull;
    int ok = 0;
    if (raw4(226, (long) page, 4096, 7, 0) != 0) {
        int fd = raw4(56, AT_FDCWD, (long) "/proc/self/mem", 1, 0);
        int wrote;
        if (fd < 0) {
            return 0;
        }
        wrote = raw4(68, fd, (long) bytes, (long) n, (long) addr);
        raw4(57, fd, 0, 0, 0);
        ok = wrote == (int) n;
    } else {
        memcpy(addr, bytes, n);
        raw4(226, (long) page, 4096, 5, 0);
        ok = 1;
    }
    if (ok) {
        clear_icache(addr, n);
    }
    return ok;
}

static int parse_hex(const char **cursor, uintptr_t *out) {
    uintptr_t value = 0;
    const char *p = *cursor;
    int digits = 0;
    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')) {
        unsigned digit = (unsigned) (*p <= '9' ? *p - '0' : *p - 'a' + 10);
        value = (value << 4) | digit;
        p++;
        digits++;
    }
    if (digits == 0) {
        return 0;
    }
    *cursor = p;
    *out = value;
    return 1;
}

static int dexhelper_ranges(uintptr_t *starts, uintptr_t *ends, int cap) {
    char *buf = (char *) malloc(512u * 1024u);
    size_t got = 0;
    size_t i = 0;
    int found = 0;
    if (buf == NULL || !read_maps(buf, 512u * 1024u, &got)) {
        free(buf);
        return 0;
    }
    while (i < got && found < cap) {
        const char *line = buf + i;
        size_t line_len = 0;
        const char *cursor;
        uintptr_t a;
        uintptr_t b;
        while (i + line_len < got && buf[i + line_len] != '\n') {
            line_len++;
        }
        cursor = line;
        if (parse_hex(&cursor, &a) && *cursor == '-') {
            cursor++;
            if (parse_hex(&cursor, &b)) {
                char saved = buf[i + line_len];
                buf[i + line_len] = '\0';
                if (strstr_local(line, "libDexHelper.so") && (strstr_local(line, "r-xp") || strstr_local(line, "rwxp"))) {
                    starts[found] = a;
                    ends[found] = b;
                    found++;
                }
                buf[i + line_len] = saved;
            }
        }
        i += line_len;
        if (i < got && buf[i] == '\n') {
            i++;
        }
    }
    free(buf);
    return found;
}

static int strstr_local(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    size_t i;
    for (i = 0; hay[i] != '\0'; i++) {
        size_t j;
        for (j = 0; j < n && hay[i + j] == needle[j]; j++) {
        }
        if (j == n) {
            return 1;
        }
    }
    return 0;
}

void pthread_exit(void *retval);

static void leave_thread(void) {
    pthread_exit(0);
}

static int patch_suicide(uintptr_t start, uintptr_t end) {
    uintptr_t p;
    int hits = 0;
    if (end < start || end - start > 0x2000000u) {
        return 0;
    }
    for (p = start; p + 24 <= end; p += 4) {
        unsigned first = *(volatile unsigned *) p;
        unsigned second = *(volatile unsigned *) (p + 4);
        unsigned third = *(volatile unsigned *) (p + 8);
        unsigned char stub[16];
        uintptr_t target;
        if (first != 0xD2800000u || second != 0x9100001Fu || third != 0xAA0003FEu) {
            continue;
        }
        if ((*(volatile unsigned *) (p + 20) & 0xFFFFFC1Fu) != 0xD61F0000u) {
            continue;
        }
        target = (uintptr_t) leave_thread;
        stub[0] = 0x50;
        stub[1] = 0x00;
        stub[2] = 0x00;
        stub[3] = 0x58;
        stub[4] = 0x00;
        stub[5] = 0x02;
        stub[6] = 0x1f;
        stub[7] = 0xd6;
        memcpy(stub + 8, &target, 8);
        if (poke((void *) p, stub, 16)) {
            hits++;
        }
    }
    return hits;
}

static void nlog_hex(const char *prefix, uintptr_t value) {
    char buf[96];
    char digits[] = "0123456789abcdef";
    size_t n = strlen(prefix);
    int i;
    if (n > 40) {
        n = 40;
    }
    memcpy(buf, prefix, n);
    for (i = 15; i >= 0; i--) {
        buf[n + (size_t) (15 - i)] = digits[(value >> (i * 4)) & 0xf];
    }
    buf[n + 16] = '\0';
    nlog(buf);
}

static int write_all(int fd, const void *buf, size_t len) {
    const char *cursor = (const char *) buf;
    size_t left = len;
    while (left > 0) {
        size_t chunk = left > 65536u ? 65536u : left;
        int wrote = raw4(64, fd, (long) cursor, (long) chunk, 0);
        if (wrote <= 0) {
            return -1;
        }
        cursor += wrote;
        left -= (size_t) wrote;
    }
    return 0;
}

static int dump_file(const char *path, const void *buf, size_t len) {
    int fd = raw4(56, AT_FDCWD, (long) path, 577, 0644);
    int status;
    if (fd < 0) {
        return fd;
    }
    status = write_all(fd, buf, len);
    raw4(57, fd, 0, 0, 0);
    return status;
}

static void dump_decoded(uintptr_t *starts, uintptr_t *ends, int count) {
    static const char *paths[] = {
            "/data/user/0/com.hypergryph.skland/cache/dh0.bin",
            "/data/user/0/com.hypergryph.skland/cache/dh1.bin",
            "/data/user/0/com.hypergryph.skland/cache/dh2.bin",
            "/data/user/0/com.hypergryph.skland/cache/dh3.bin",
    };
    int range;
    char *maps = (char *) malloc(512u * 1024u);
    size_t maps_len = 0;
    for (range = 0; range < count && range < 4; range++) {
        size_t len = (size_t) (ends[range] - starts[range]);
        if (dump_file(paths[range], (void *) starts[range], len) != 0) {
            nlog("dump failed");
            break;
        }
        nlog_hex("dumped ", starts[range]);
    }
    if (maps != NULL && read_maps(maps, 512u * 1024u, &maps_len)) {
        dump_file("/data/user/0/com.hypergryph.skland/cache/dh.maps", maps, maps_len);
    }
    free(maps);
}

__attribute__((noinline, optnone)) static int same_bytes(const void *left, const void *right, size_t n) {
    const unsigned char *a = (const unsigned char *) left;
    const unsigned char *b = (const unsigned char *) right;
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int poke_mem(void *addr, const void *bytes, size_t n) {
    int fd = raw4(56, AT_FDCWD, (long) "/proc/self/mem", 1, 0);
    int wrote;
    if (fd < 0) {
        return 0;
    }
    wrote = raw4(68, fd, (long) bytes, (long) n, (long) addr);
    raw4(57, fd, 0, 0, 0);
    if (wrote == (int) n) {
        clear_icache(addr, n);
        return 1;
    }
    return 0;
}

__attribute__((noinline, optnone)) static int patch_late(uintptr_t start, uintptr_t end) {
    static const unsigned char maps_old[] = "/proc/self/maps";
    static const unsigned char maps_new[] = "/proc/self/fd/9";
    static const unsigned char udf_bad[] = {
            0xea, 0x03, 0x1f, 0xaa, 0xe9, 0x00, 0x00, 0x00, 0xea, 0x6a, 0x6a, 0x38
    };
    static const unsigned char udf_fix[] = {0xe9, 0x03, 0x0a, 0xaa};
    uintptr_t p;
    int hits = 0;
    if (end < start || end - start > 0x2000000u) {
        return 0;
    }
    for (p = start; p + 15 <= end; p++) {
        if (same_bytes((void *) p, maps_old, 15) && poke_mem((void *) p, maps_new, 15)) {
            hits++;
            nlog("maps path");
        }
    }
    for (p = start; p + 12 <= end; p += 4) {
        if (same_bytes((void *) p, udf_bad, 12) && poke_mem((void *) (p + 4), udf_fix, 4)) {
            hits++;
            nlog("udf restored");
        }
    }
    return hits;
}

static void nap20(void) {
    long req[2];
    req[0] = 0;
    req[1] = 20000000L;
    raw4(101, (long) req, 0, 0, 0);
}

static void *watch_dexhelper(void *arg) {
    int hot = 0;
    int ticks = 0;
    (void) arg;
    while (ticks < 50000) {
        uintptr_t starts[8];
        uintptr_t ends[8];
        int count = dexhelper_ranges(starts, ends, 8);
        int range;
        int suicide = 0;
        if (count > 0) {
            for (range = 0; range < count; range++) {
                suicide += patch_suicide(starts[range], ends[range]);
                patch_late(starts[range], ends[range]);
            }
            if (suicide > 0) {
                nlog_hex("suicide ", (uintptr_t) suicide);
            }
            if (hot < 800) {
                hot++;
                continue;
            }
        }
        nap20();
        ticks++;
    }
    nlog("watch done");
    return NULL;
}

void Java_dev_elin_teenpopup_TeenPopupModule_teen_1refresh_1maps(void *env, void *clazz) {
    (void) env;
    (void) clazz;
    refresh_maps_fd();
}

__attribute__((constructor)) static void hide_init(void) {
    pthread_t thread;
    void *loglib = dlopen("liblog.so", RTLD_NOW);
    if (loglib != NULL) {
        log_print = (log_fn) dlsym(loglib, "__android_log_print");
    }
    refresh_maps_fd();
    if (pthread_create(&thread, NULL, watch_dexhelper, NULL) != 0) {
        nlog("watch thread failed");
    }
}
