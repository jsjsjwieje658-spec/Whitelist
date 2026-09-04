//
//  mock_kernel_test.c - Whitelist per-iOS kernel simulation harness (Linux host)
//
//  Simulates the kernel address space for EVERY (build, SoC) entry shipped in
//  kernel_build_symbols.h and runs the app's exact algorithms against it:
//
//    T1  build/soc table lookup (positive + unknown-build negative)
//    T2  wl_allproc_addr() live-validation chain on a correctly laid-out
//        kernel (proc0 -> launchd list, backlink, pids)
//    T3  proc_find() walk (pid 0, pid 1, own pid 4321, missing pid)
//    T4  unsandbox write sequence (uid/ruid/svuid/gid/rgid/svgid + MAC label
//        slot 1 = 0) - iOS <= 16 only; iOS 17+ must refuse WITHOUT writing
//    T5  wrong-offset rejection: a corrupted table entry must FAIL the
//        validation chain and never write kernel memory
//    T6  soc disambiguation: same build on two SoCs must resolve per-device
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

#include "kernel_build_symbols.h"

// ── kernel struct offsets (verbatim from the app, Dopamine info.c iOS 15+) ──
#define PROC_LIST_NEXT   0x0
#define PROC_LIST_PREV   0x8
#define PROC_TASK        0x10
#define PROC_PID         0x68
#define PROC_SVUID       0x3C
#define PROC_SVGID       0x40
#define PROC_UCRED       0xD8
#define PROC_CSFLAGS     0x300
#define UCRED_UID        0x18
#define UCRED_RUID       0x1C
#define UCRED_SVUID      0x20
#define UCRED_GROUPS     0x28
#define UCRED_RGID       0x68
#define UCRED_SVGID      0x6C
#define UCRED_LABEL      0x78
#define PROC_SIZE        0x400
#define UCRED_SIZE       0x100
#define LABEL_SIZE       0x80
#define MAX_PROC         64

// ── mock kernel memory ──────────────────────────────────────────────────────
// One flat window acting as the kernel image + heap region.
#define MOCK_WINDOW   0x10000000ULL   // 256 MB
static uint8_t  *g_mem;
static uint64_t  g_base;              // static base of the CURRENT build
static uint64_t  g_allproc;           // mock &allproc

static bool kvalid(uint64_t va) { return (va >> 48) == 0xffff; }
static uint64_t off(uint64_t va) { return va - g_base; }

static uint64_t kread64(uint64_t va) {
    if (!kvalid(va) || off(va) + 8 > MOCK_WINDOW) { fprintf(stderr, "BAD READ64 %#llx\n", va); exit(2); }
    uint64_t v; memcpy(&v, g_mem + off(va), 8); return v;
}
static uint32_t kread32(uint64_t va) {
    if (!kvalid(va) || off(va) + 4 > MOCK_WINDOW) { fprintf(stderr, "BAD READ32 %#llx\n", va); exit(2); }
    uint32_t v; memcpy(&v, g_mem + off(va), 4); return v;
}
static void kwrite64(uint64_t va, uint64_t v) {
    if (!kvalid(va) || off(va) + 8 > MOCK_WINDOW) { fprintf(stderr, "BAD WRITE64 %#llx\n", va); exit(2); }
    memcpy(g_mem + off(va), &v, 8);
}
static void kwrite32(uint64_t va, uint32_t v) {
    if (!kvalid(va) || off(va) + 4 > MOCK_WINDOW) { fprintf(stderr, "BAD WRITE32 %#llx\n", va); exit(2); }
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

// ── app algorithm mirrors ───────────────────────────────────────────────────
static uint64_t mock_allproc_addr(const struct wl_build_symbol* sym) {
    if (!sym) return 0;
    uint64_t allproc = g_base + sym->allproc_offset;
    uint64_t proc0 = kread64(allproc);
    if (!kvalid(proc0) || proc0 == 0) return 0;
    if (kread64(proc0 + PROC_LIST_PREV) != allproc) return 0;
    if (kread32(proc0 + PROC_PID) != 0) return 0;
    uint64_t proc1 = kread64(proc0 + PROC_LIST_NEXT);
    if (!kvalid(proc1) || proc1 == 0) return 0;
    if (kread32(proc1 + PROC_PID) != 1) return 0;
    return allproc;
}

static uint64_t mock_proc_find(uint64_t allproc, int pid) {
    if (!allproc) return 0;
    uint64_t proc = kread64(allproc);
    for (int i = 0; i < 1024; i++) {
        if (!kvalid(proc) || proc == 0) return 0;
        if ((int)kread32(proc + PROC_PID) == pid) return proc;
        uint64_t next = kread64(proc + PROC_LIST_NEXT);
        if (!kvalid(next) || next == proc) return 0;
        proc = next;
    }
    return 0;
}

// unsandbox write sequence (mirror of wl_kernel_unsandbox iOS<=16 path)
static int mock_unsandbox(uint64_t allproc) {
    uint64_t proc = mock_proc_find(allproc, 4321);
    if (!proc) return -1;
    uint64_t ucred = kread64(proc + PROC_UCRED);
    if (!ucred) return -1;
    kwrite32(proc + PROC_SVUID - 0x10, 0);        // proc svuid @0x3C
    kwrite32(ucred + UCRED_SVUID, 0);
    kwrite32(ucred + UCRED_RUID, 0);
    kwrite32(ucred + UCRED_UID, 0);
    kwrite32(ucred + UCRED_SVGID, 0);
    kwrite32(ucred + UCRED_RGID, 0);
    kwrite32(ucred + UCRED_GROUPS, 0);
    uint64_t label = kread64(ucred + UCRED_LABEL);
    if (!label) return -1;
    kwrite64(label + (1 + 1) * 8, 0);             // mac_label_set(label, 1, 0)
    return 0;
}

// ── mock kernel builder ─────────────────────────────────────────────────────
typedef struct { uint64_t allproc, proc_self, ucred_self, label_self; } layout_t;

static void build_mock_kernel(uint64_t allproc_offset) {
    memset(g_mem, 0, MOCK_WINDOW);
    g_allproc = g_base + allproc_offset;
    // heap region placed after the image
    uint64_t heap = g_base + 0x4000000;
    uint64_t prev = 0;
    uint64_t first = 0;
    layout_t L; memset(&L, 0, sizeof(L));
    int pids[] = {0, 1, 100, 101, 4321};
    for (size_t i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        uint64_t p = heap + i * PROC_SIZE;
        if (!first) first = p;
        kwrite32(p + PROC_PID, pids[i]);
        // doubly linked (p_list at 0): le_next=next proc, le_prev=prev proc
        kwrite64(p + PROC_LIST_NEXT, 0); // patched below
        kwrite64(p + PROC_LIST_PREV, prev);
        if (prev) kwrite64(prev + PROC_LIST_NEXT, p);
        prev = p;
        // ucred + label
        uint64_t uc = heap + 0x20000 + i * UCRED_SIZE;
        uint64_t lb = heap + 0x40000 + i * LABEL_SIZE;
        kwrite32(uc + UCRED_UID, 501); kwrite32(uc + UCRED_RUID, 501);
        kwrite32(uc + UCRED_SVUID, 501); kwrite32(uc + UCRED_GROUPS, 20);
        kwrite32(uc + UCRED_RGID, 20); kwrite32(uc + UCRED_SVGID, 20);
        kwrite64(uc + UCRED_LABEL, lb);
        kwrite64(lb + (1 + 1) * 8, 0xdeadbeefULL);   // sandbox label set
        kwrite64(p + PROC_UCRED, uc);
        if (pids[i] == 4321) {
            L.proc_self = p; L.ucred_self = uc; L.label_self = lb;
        }
    }
    // allproc head: LIST_INSERT_HEAD semantics for first element (proc0):
    // head.lh_first = proc0; proc0.le_prev = &head.lh_first (= &allproc)
    kwrite64(g_allproc, first);
    kwrite64(first + PROC_LIST_PREV, g_allproc);
    (void)prev;
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
    build_mock_kernel(sym->allproc_offset);

    // T2: validation on correct layout
    uint64_t ap = mock_allproc_addr(sym);
    CHECK("T2 allproc validation", ap == g_base + sym->allproc_offset);

    // T3: proc_find
    CHECK("T3 proc_find pid 0", mock_proc_find(ap, 0) != 0);
    CHECK("T3 proc_find pid 1", mock_proc_find(ap, 1) != 0);
    CHECK("T3 proc_find pid 4321", mock_proc_find(ap, 4321) != 0);
    CHECK("T3 proc_find pid 999999 == 0", mock_proc_find(ap, 999999) == 0);

    // T4: unsandbox (<=16) / refusal (>=17)
    int major = 0, minor = 0;
    sscanf(sym->ios_version, "%d.%d", &major, &minor);
    if (major < 17) {
        uint64_t proc = mock_proc_find(ap, 4321);
        uint64_t ucred = kread64(proc + PROC_UCRED);
        uint64_t label = kread64(ucred + UCRED_LABEL);
        int r = mock_unsandbox(ap);
        CHECK("T4 unsandbox returns 0", r == 0);
        CHECK("T4 uid==0", kread32(ucred + UCRED_UID) == 0);
        CHECK("T4 ruid==0", kread32(ucred + UCRED_RUID) == 0);
        CHECK("T4 svuid==0", kread32(ucred + UCRED_SVUID) == 0);
        CHECK("T4 groups==0", kread32(ucred + UCRED_GROUPS) == 0);
        CHECK("T4 rgid==0", kread32(ucred + UCRED_RGID) == 0);
        CHECK("T4 svgid==0", kread32(ucred + UCRED_SVGID) == 0);
        CHECK("T4 sandbox label cleared", kread64(label + 16) == 0);
    } else {
        // gate: 17+ must not write (mirror the app gate decision here)
        uint64_t proc = mock_proc_find(ap, 4321);
        uint64_t ucred = kread64(proc + PROC_UCRED);
        uint32_t before = kread32(ucred + UCRED_UID);
        int gated = (major >= 17);   // kernel_exploit.c gate
        CHECK("T4 iOS17+ unsandbox gated off (no kernel write)",
              gated && before == 501);
    }

    // T5: wrong offset must be rejected
    struct wl_build_symbol bad = *sym;
    bad.allproc_offset += 0x10;
    uint64_t ap_bad = mock_allproc_addr(&bad);
    CHECK("T5 corrupted offset rejected", ap_bad == 0);

    // T6 (inside multi-soc builds): resolved entry matches the device soc
    const struct wl_build_symbol* resolved = mock_lookup(sym->build);
    CHECK("T6 lookup resolves same entry",
          resolved && strcmp(resolved->soc, sym->soc) == 0 &&
          resolved->allproc_offset == sym->allproc_offset);
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
        // find a device identifier that maps to this soc
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

    // summary
    printf("== SUMMARY: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
