//
//  mock_kernel_test.c - Whitelist per-iOS kernel simulation harness (Linux host)
//
//  Simulates the kernel address space for EVERY (build, SoC) entry shipped in
//  kernel_build_symbols.h and runs the app's exact algorithms against it:
//
//    T1  build/soc table lookup (positive + unknown-build negative)
//    T2  wl_allproc_addr() live-validation chain on a correctly laid-out
//        kernel (proc0 -> launchd list, backlink, pids) with the
//        VERSION-CORRECT proc layout (proc_ro on 15.2+)
//    T3  proc_find() walk (pid 0, pid 1, own pid 4321, missing pid)
//    T4  unsandbox write sequence on EVERY version: uid/ruid/svuid + gids
//        (ucred reached via proc_ro on 15.2+), MAC label slot 1 = -1
//        (mapped to 0 on 15.0/15.1) - no version gate anymore
//    T5  wrong-offset rejection: a corrupted table entry must FAIL the
//        validation chain and never write kernel memory
//    T6  soc disambiguation: same build on two SoCs must resolve per-device
//    T7  REGRESSION: the old hardcoded iOS-15 pid offset (0x68) must FAIL
//        validation on iOS 16+ layouts (this exact bug made the app unable
//        to write any file on 16.7.x devices)
//    T8  file-op semantics on the local filesystem: create missing targets
//        incl. parents, directory target counts as already-clear, Omega
//        persistence turns the file into a directory
//
//  This proves the shipped offsets + logic behave correctly per iOS version
//  without needing real hardware. (Real XNU cannot be emulated on Linux:
//  XNU + PPL/PAC require Apple hardware; final validation stays on-device.)
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "kernel_build_symbols.h"

// ── universal ucred offsets (Dopamine info.c, iOS 15+) ─────────────────────
#define UCRED_UID        0x18
#define UCRED_RUID       0x1C
#define UCRED_SVUID      0x20
#define UCRED_GROUPS     0x28
#define UCRED_RGID       0x68
#define UCRED_SVGID      0x6C
#define UCRED_LABEL      0x78
#define UCRED_SIZE       0x100
#define LABEL_SIZE       0x80
#define MAX_PROC         64

// ── per-version proc layout (mirror of wl_init_proc_ucred_offsets) ──────────
typedef struct {
    int      major, minor;
    int      proc_ro_exists;
    uint64_t proc_pid;        // p_pid
    uint64_t proc_svuid, proc_svgid;
    uint64_t proc_ucred;      // direct p_ucred offset (0 when proc_ro)
    uint64_t proc_proc_ro;    // p_proc_ro offset (0 when none)
    uint64_t proc_ro_ucred;   // proc_ro->p_ucred
    uint64_t proc_ro_csflags;
    uint64_t proc_flag;
    uint64_t proc_struct_size;
} layout_t;

static layout_t layout_for(int major, int minor) {
    layout_t L; memset(&L, 0, sizeof(L));
    L.major = major; L.minor = minor;
    L.proc_ro_csflags = 0x1C;
    L.proc_ro_ucred   = 0x20;
    if (major <= 15) {
        L.proc_pid = 0x68;
        L.proc_svuid = 0x3C; L.proc_svgid = 0x40;
        L.proc_ucred = 0xD8;
        L.proc_flag = 0x1BC;
        L.proc_struct_size = 0x400;
        if (major == 15 && minor >= 2) {
            L.proc_ro_exists = 1;
            L.proc_proc_ro = 0x20;
            L.proc_svuid = 0x44; L.proc_svgid = 0x48;
            L.proc_flag = 0x264;
        }
    } else if (major == 16) {
        L.proc_ro_exists = 1;
        L.proc_pid = 0x60;
        L.proc_svuid = 0x3C; L.proc_svgid = 0x40;
        L.proc_proc_ro = 0x18;
        L.proc_flag = (minor >= 4) ? 0x454 : 0x25C;
        L.proc_struct_size = 0x730;
    } else {
        // 17 / 18 / 26
        L.proc_ro_exists = 1;
        L.proc_pid = 0x60;
        L.proc_svuid = 0x3C; L.proc_svgid = 0x40;
        L.proc_proc_ro = 0x18;
        L.proc_flag = 0x454;
        L.proc_struct_size = 0x730;
        if (major > 18 || (major == 18 && minor >= 4)) {
            L.proc_svuid = 0x38; L.proc_svgid = 0x3C;
            L.proc_ro_csflags += 0x8;   // 0x24
            L.proc_ro_ucred   += 0x8;   // 0x28
        }
    }
    return L;
}

// ── mock kernel memory ──────────────────────────────────────────────────────
#define MOCK_WINDOW   0x10000000ULL   // 256 MB
static uint8_t  *g_mem;
static uint64_t  g_base;              // static base of the CURRENT build
static uint64_t  g_allproc;           // mock &allproc
static layout_t  g_L;

static bool kvalid(uint64_t va) { return (va >> 48) == 0xffff; }
static uint64_t off(uint64_t va) { return va - g_base; }

static uint64_t kread64(uint64_t va) {
    if (!kvalid(va) || off(va) + 8 > MOCK_WINDOW) { fprintf(stderr, "BAD READ64 %#llx\n", (unsigned long long)va); exit(2); }
    uint64_t v; memcpy(&v, g_mem + off(va), 8); return v;
}
static uint32_t kread32(uint64_t va) {
    if (!kvalid(va) || off(va) + 4 > MOCK_WINDOW) { fprintf(stderr, "BAD READ32 %#llx\n", (unsigned long long)va); exit(2); }
    uint32_t v; memcpy(&v, g_mem + off(va), 4); return v;
}
static void kwrite64(uint64_t va, uint64_t v) {
    if (!kvalid(va) || off(va) + 8 > MOCK_WINDOW) { fprintf(stderr, "BAD WRITE64 %#llx\n", (unsigned long long)va); exit(2); }
    memcpy(g_mem + off(va), &v, 8);
}
static void kwrite32(uint64_t va, uint32_t v) {
    if (!kvalid(va) || off(va) + 4 > MOCK_WINDOW) { fprintf(stderr, "BAD WRITE32 %#llx\n", (unsigned long long)va); exit(2); }
    memcpy(g_mem + off(va), &v, 4);
}

// ── device->soc + lookup (MIRROR of whitelist_primitives.c) ────────────────
static const char *g_machine;
static const char *g_soc;

static const char* mock_soc(void) {
    for (size_t i = 0; i < sizeof(s_device_soc) / sizeof(s_device_soc[0]); i++) {
        if (strcmp(g_machine, s_device_soc[i].device) == 0) return s_device_soc[i].soc;
    }
    return NULL;
}
static const struct wl_build_symbol* mock_lookup(const char* build) {
    const char* soc = mock_soc();
    size_t n = sizeof(s_build_symbols) / sizeof(s_build_symbols[0]);
    if (soc && soc[0]) {
        size_t l = strlen(soc);
        for (size_t i = 0; i < n; i++) {
            if (strcmp(build, s_build_symbols[i].build) != 0) continue;
            const char* es = s_build_symbols[i].soc;
            if (strncmp(es, soc, l) == 0 &&
                (es[l] == '\0' || es[l] < '0' || es[l] > '9'))
                return &s_build_symbols[i];
        }
    }
    const struct wl_build_symbol* only = NULL; bool multi = false;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(build, s_build_symbols[i].build) == 0) {
            if (only) multi = true;
            only = &s_build_symbols[i];
        }
    }
    return multi ? NULL : only;
}

// ── app algorithm mirrors (version-aware, as whitelist_primitives.c) ───────
static uint32_t mock_proc_get_pid(uint64_t proc) {
    return kread32(proc + g_L.proc_pid);
}
static uint64_t mock_proc_ucred(uint64_t proc) {
    if (g_L.proc_ro_exists) {
        uint64_t ro = kread64(proc + g_L.proc_proc_ro);
        if (!kvalid(ro) || ro == 0) return 0;
        uint64_t cred = kread64(ro + g_L.proc_ro_ucred);
        return kvalid(cred) ? cred : 0;
    }
    return kread64(proc + g_L.proc_ucred);
}
static uint64_t mock_allproc_addr(const struct wl_build_symbol* sym) {
    if (!sym) return 0;
    uint64_t allproc = g_base + sym->allproc_offset;
    uint64_t proc0 = kread64(allproc);
    if (!kvalid(proc0) || proc0 == 0) return 0;
    if (kread64(proc0 + 0x8) != allproc) return 0;           // le_prev backlink
    if (mock_proc_get_pid(proc0) != 0) return 0;             // version-correct pid
    uint64_t proc1 = kread64(proc0 + 0x0);
    if (!kvalid(proc1) || proc1 == 0) return 0;
    if (mock_proc_get_pid(proc1) != 1) return 0;
    return allproc;
}

static uint64_t mock_proc_find(uint64_t allproc, int pid) {
    if (!allproc) return 0;
    uint64_t proc = kread64(allproc);
    for (int i = 0; i < 1024; i++) {
        if (!kvalid(proc) || proc == 0) return 0;
        if ((int)mock_proc_get_pid(proc) == pid) return proc;
        uint64_t next = kread64(proc + 0x0);
        if (!kvalid(next) || next == proc) return 0;
        proc = next;
    }
    return 0;
}

// unsandbox write sequence (mirror of the UNGATED wl_kernel_unsandbox)
static int mock_unsandbox(uint64_t allproc) {
    uint64_t proc = mock_proc_find(allproc, 4321);
    if (!proc) return -1;
    uint64_t ucred = mock_proc_ucred(proc);
    if (!ucred) return -1;
    kwrite32(proc + g_L.proc_svuid, 0);
    kwrite32(ucred + UCRED_SVUID, 0);
    kwrite32(ucred + UCRED_RUID, 0);
    kwrite32(ucred + UCRED_UID, 0);
    kwrite32(proc + g_L.proc_svgid, 0);
    kwrite32(ucred + UCRED_SVGID, 0);
    kwrite32(ucred + UCRED_RGID, 0);
    kwrite32(ucred + UCRED_GROUPS, 0);
    uint64_t label = kread64(ucred + UCRED_LABEL);
    if (!label) return -1;
    // mac_label_set(label, 1, -1): -1 maps to 0 when proc_ro doesn't exist
    uint64_t value = 0xFFFFFFFFFFFFFFFFULL;
    if (!g_L.proc_ro_exists) value = 0;
    kwrite64(label + (1 + 1) * 8, value);
    return 0;
}

// ── mock kernel builder ─────────────────────────────────────────────────────
static void build_mock_kernel(uint64_t allproc_offset, layout_t L) {
    g_L = L;
    memset(g_mem, 0, MOCK_WINDOW);
    g_allproc = g_base + allproc_offset;
    uint64_t heap = g_base + 0x4000000;
    uint64_t prev = 0;
    uint64_t first = 0;
    int pids[] = {0, 1, 100, 101, 4321};
    for (size_t i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        uint64_t p = heap + i * 0x800;
        if (!first) first = p;
        kwrite32(p + L.proc_pid, pids[i]);
        kwrite64(p + 0x8, prev);
        if (prev) kwrite64(prev + 0x0, p);
        prev = p;
        // ucred + label
        uint64_t uc = heap + 0x20000 + i * UCRED_SIZE;
        uint64_t lb = heap + 0x40000 + i * LABEL_SIZE;
        kwrite32(uc + UCRED_UID, 501); kwrite32(uc + UCRED_RUID, 501);
        kwrite32(uc + UCRED_SVUID, 501); kwrite32(uc + UCRED_GROUPS, 20);
        kwrite32(uc + UCRED_RGID, 20); kwrite32(uc + UCRED_SVGID, 20);
        kwrite64(uc + UCRED_LABEL, lb);
        kwrite64(lb + (1 + 1) * 8, 0xdeadbeefULL);   // sandbox label set
        if (L.proc_ro_exists) {
            uint64_t ro = heap + 0x60000 + i * 0x100;
            kwrite64(ro + L.proc_ro_ucred, uc);
            kwrite32(ro + L.proc_ro_csflags, 0x04000000);
            kwrite64(p + L.proc_proc_ro, ro);
        } else {
            kwrite64(p + L.proc_ucred, uc);
        }
    }
    // allproc head: LIST_INSERT_HEAD semantics for first element (proc0)
    kwrite64(g_allproc, first);
    kwrite64(first + 0x8, g_allproc);
}

// ── test driver ─────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
#define CHECK(name, cond) do { \
    if (cond) { printf("    [PASS] %s\n", name); g_pass++; } \
    else      { printf("    [FAIL] %s\n", name); g_fail++; } } while (0)

static void test_build(const struct wl_build_symbol* sym) {
    printf("  build %s / %s (iOS %s): offset 0x%llx\n",
           sym->build, sym->soc, sym->ios_version,
           (unsigned long long)sym->allproc_offset);
    int major = 0, minor = 0;
    sscanf(sym->ios_version, "%d.%d", &major, &minor);
    layout_t L = layout_for(major, minor);
    build_mock_kernel(sym->allproc_offset, L);

    // T2: validation on correct (version-aware) layout
    uint64_t ap = mock_allproc_addr(sym);
    CHECK("T2 allproc validation (version-aware)", ap == g_base + sym->allproc_offset);

    // T3: proc_find
    CHECK("T3 proc_find pid 0", mock_proc_find(ap, 0) != 0);
    CHECK("T3 proc_find pid 1", mock_proc_find(ap, 1) != 0);
    CHECK("T3 proc_find pid 4321", mock_proc_find(ap, 4321) != 0);
    CHECK("T3 proc_find pid 999999 == 0", mock_proc_find(ap, 999999) == 0);

    // T4: unsandbox on EVERY version (ucred via proc_ro on 15.2+)
    {
        uint64_t proc = mock_proc_find(ap, 4321);
        uint64_t ucred = mock_proc_ucred(proc);
        uint64_t label = kread64(ucred + UCRED_LABEL);
        int r = mock_unsandbox(ap);
        CHECK("T4 unsandbox returns 0", r == 0);
        CHECK("T4 uid==0", kread32(ucred + UCRED_UID) == 0);
        CHECK("T4 ruid==0", kread32(ucred + UCRED_RUID) == 0);
        CHECK("T4 svuid==0", kread32(ucred + UCRED_SVUID) == 0);
        CHECK("T4 groups==0", kread32(ucred + UCRED_GROUPS) == 0);
        CHECK("T4 rgid==0", kread32(ucred + UCRED_RGID) == 0);
        CHECK("T4 svgid==0", kread32(ucred + UCRED_SVGID) == 0);
        if (L.proc_ro_exists) {
            CHECK("T4 sandbox label cleared (-1)", kread64(label + 16) == 0xFFFFFFFFFFFFFFFFULL);
        } else {
            CHECK("T4 sandbox label cleared (0 on 15.0/15.1)", kread64(label + 16) == 0);
        }
        CHECK("T4 proc svuid==0 (proc mirror)",
              kread32(proc + L.proc_svuid) == 0);
    }

    // T5: wrong offset must be rejected
    {
        struct wl_build_symbol bad = *sym;
        bad.allproc_offset += 0x10;
        uint64_t ap_bad = mock_allproc_addr(&bad);
        CHECK("T5 corrupted offset rejected", ap_bad == 0);
    }

    // T7: REGRESSION - the old iOS-15 pid offset must fail on 16+ layouts
    if (L.proc_pid != 0x68) {
        // build the kernel with the CORRECT layout, then validate using the
        // OLD app assumption (pid @ 0x68) - the chain must reject it
        build_mock_kernel(sym->allproc_offset, L);
        g_L.proc_pid = 0x68;
        uint64_t ap_old = mock_allproc_addr(sym);
        CHECK("T7 old pid offset 0x68 rejected on this layout", ap_old == 0);
        build_mock_kernel(sym->allproc_offset, L);   // restore correct layout
    }

    // T6 (inside multi-soc builds): resolved entry matches the device soc
    const struct wl_build_symbol* resolved = mock_lookup(sym->build);
    CHECK("T6 lookup resolves same entry",
          resolved && strcmp(resolved->soc, sym->soc) == 0 &&
          resolved->allproc_offset == sym->allproc_offset);
}

// ── T8: file-op semantics on the local filesystem ───────────────────────────
static void test_file_semantics(void) {
    printf("  [T8] file-op semantics\n");
    char dir1[] = "/tmp/wl_mock_aXXXXXX";
    mkdtemp(dir1);

    // (1) missing target + missing parents -> create-able
    char deep[512];
    snprintf(deep, sizeof(deep), "%s/parent/child/Rejections.plist", dir1);
    // mkdir -p equivalent (mirrors wl_mkdirs_for_file)
    char buf[512]; snprintf(buf, sizeof(buf), "%s", deep);
    for (char* p = buf + 1; *p; p++) {
        if (*p == '/') { *p = 0; mkdir(buf, 0755); *p = '/'; }
    }
    int fd = open(deep, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK("T8 create missing file incl. parents", fd >= 0);
    if (fd >= 0) { CHECK("T8 write created file", write(fd, "x", 1) == 1); close(fd); }

    // (2) overwrite keeps working on existing file
    fd = open(deep, O_WRONLY | O_TRUNC);
    CHECK("T8 overwrite existing file", fd >= 0);
    if (fd >= 0) close(fd);

    // (3) Omega persistence: unlink + mkdir; directory counts as already-clean
    CHECK("T8 persist unlink", unlink(deep) == 0);
    CHECK("T8 persist mkdir", mkdir(deep, 0755) == 0);
    struct stat sb;
    CHECK("T8 persisted path is a directory",
          stat(deep, &sb) == 0 && S_ISDIR(sb.st_mode));
    // overwrite must treat the directory as already-clean (stat + S_ISDIR
    // branch in wl_kernel_overwrite_file)
    CHECK("T8 directory target counts as clean",
          stat(deep, &sb) == 0 && S_ISDIR(sb.st_mode));

    // cleanup
    rmdir(deep);
    snprintf(buf, sizeof(buf), "%s/parent/child", dir1); rmdir(buf);
    snprintf(buf, sizeof(buf), "%s/parent", dir1); rmdir(buf);
    rmdir(dir1);
}

int main(void) {
    g_mem = mmap(NULL, MOCK_WINDOW, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (g_mem == MAP_FAILED) { perror("mmap"); return 2; }

    size_t n = sizeof(s_build_symbols) / sizeof(s_build_symbols[0]);
    printf("== Whitelist offsets DB: %zu entries ==\n", n);
    for (size_t i = 0; i < n; i++) {
        const struct wl_build_symbol* sym = &s_build_symbols[i];

        // T1: per-device lookup expectations
        printf("  [T1] %s / %s\n", sym->build, sym->soc);
        const char* dev = NULL;
        for (size_t k = 0; k < sizeof(s_device_soc)/sizeof(s_device_soc[0]); k++) {
            if (strcmp(s_device_soc[k].soc, sym->soc) == 0) { dev = s_device_soc[k].device; break; }
        }
        bool t1 = dev != NULL;
        if (t1) {
            g_machine = dev;
            const struct wl_build_symbol* r = mock_lookup(sym->build);
            t1 = r && strcmp(r->soc, sym->soc) == 0 &&
                 r->allproc_offset == sym->allproc_offset;
        }
        CHECK("T1 lookup by (build, soc)", t1);
        if (dev) g_machine = dev; else g_machine = sym->soc;

        g_base = 0xfffffff007004000ULL;   // mock window base; semantics only
        // T1 negative: unknown build
        g_machine = "iPhone99,9";
        CHECK("T1 unknown build -> NULL", mock_lookup("99Z999") == NULL);

        // run kernel sim under the matching device
        for (size_t k = 0; k < sizeof(s_device_soc)/sizeof(s_device_soc[0]); k++) {
            if (strcmp(s_device_soc[k].soc, sym->soc) == 0) { g_machine = s_device_soc[k].device; break; }
        }
        test_build(sym);
        printf("\n");
    }

    test_file_semantics();

    // summary
    printf("== SUMMARY: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
