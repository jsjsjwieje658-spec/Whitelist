#!/usr/bin/env python3
# Multi-iOS allproc offsets pipeline (Dopamine-style, offline).
#
# For each (device, iOS version) it:
#   1. resolves the official Apple IPSW via api.ipsw.me,
#   2. range-downloads ONLY the kernelcache member (IPSW is 6-9 GB, kernelcache ~50-150 MB),
#   3. IMG4 -> IM4P -> decompress (LZFSE / LZSS / plain),
#   4. parses the Mach-O kernel image, derives the static base,
#   5. finds &allproc with TWO independent methods and cross-checks:
#        A) proc0 list-head signature (allproc.lh_first -> proc0, proc0.le_prev -> &allproc,
#           proc0.p_pid == 0, next pid == 1 launchd) - try candidate p_pid offsets
#        B) XPF port: "shutdownwait" string -> adrp+add xref -> first unsigned ldr -> &allproc
#   6. appends {build, soc, staticBase, allproc_offset, ...} to offsets_db.json
#
# usage:
#   build_offsets_db.py --device iPhone14,2 --version 17        # one build
#   build_offsets_db.py --matrix                                # whole matrix
#   build_offsets_db.py --verify-local                          # re-verify 20H392 dec bin
import argparse, json, os, struct, subprocess, shutil, sys, time, urllib.request

BASE      = '/home/z/my-project'
WORK      = os.path.join(BASE, 'kc_work')
CACHE     = os.path.join(BASE, 'ipsw_cache')
LZFSE_BIN = os.path.join(BASE, 'scripts/bin/lzfse')
DB_PATH   = os.path.join(BASE, 'download/offsets_db.json')
REPORT    = os.path.join(BASE, 'download/offsets_report.md')

MATRIX = [
    ("iPhone10,5", "16.7"),   # A11  t8015 - user device (16.7.16/20H392, prior session)
    ("iPhone13,2", "16"),     # A14  t8101 - arm64e + PPL-era iOS 16.x
    ("iPhone14,2", "17"),     # A15  t8120 - iOS 17.x
    ("iPhone15,2", "18"),     # A16  t8140 - iOS 18.x
    ("iPhone17,1", "26"),     # A18 Pro      - iOS 26.x
]
PID_OFF_CANDIDATES = [0x68, 0x60, 0x6C, 0x70, 0x74, 0x58, 0x78]
MIN_FREE_DISK      = 1_500_000_000

def log(*a):  print(*a, flush=True)

# ─────────────────────────── ipsw.me helpers ───────────────────────────
def device_json(identifier):
    os.makedirs(CACHE, exist_ok=True)
    p = os.path.join(CACHE, f'{identifier.replace(",", "_")}.json')
    if os.path.exists(p) and os.path.getsize(p) > 1000:
        return json.load(open(p))
    url = f'https://api.ipsw.me/v4/device/{identifier}?type=ipsw'
    with urllib.request.urlopen(url, timeout=60) as r:
        d = json.load(r)
    json.dump(d, open(p, 'w'))
    return d

def vtuple(v):
    out = []
    for part in v.split('.'):
        try: out.append(int(part))
        except ValueError: out.append(0)
    return tuple(out)

def pick_firmware(dev, prefix):
    cands = [f for f in dev['firmwares'] if f['version'].startswith(prefix)]
    if not cands:
        return None
    cands.sort(key=lambda f: vtuple(f['version']), reverse=True)
    best_ver = cands[0]['version']
    same = [f for f in cands if f['version'] == best_ver]
    same.sort(key=lambda f: 0 if f.get('signed') else 1)
    return same[0]

# ─────────────────────────── zip range fetch ───────────────────────────
def fetch_range(url, start, end):
    req = urllib.request.Request(url, headers={'Range': f'bytes={start}-{end}'})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.read()
        except Exception as e:
            if attempt == 2: raise
            log(f'  retry {attempt+1}: {e}'); time.sleep(3)

def fetch_kernelcache_member(url, out_path):
    req = urllib.request.Request(url, method='HEAD')
    with urllib.request.urlopen(req, timeout=60) as r:
        total = int(r.headers['Content-Length'])
    log(f'  ipsw total {total/1e9:.2f} GB')
    tail = fetch_range(url, total - 1_000_000, total - 1)
    z64 = tail.rfind(b'PK\x06\x06')
    if z64 >= 0:
        (_, _, _, _, _, _, _, n_total, cd_size, cd_ofs) = struct.unpack('<IQHHIIQQQQ', tail[z64:z64+56])
    else:
        e = tail.rfind(b'PK\x05\x06')
        assert e >= 0, 'no EOCD'
        (_, cd_count, cd_size, cd_ofs) = struct.unpack('<IHHHII', tail[e+4:e+22])
        n_total = cd_count
    base = total - len(tail)
    cd = tail[cd_ofs - base: cd_ofs - base + cd_size] if cd_ofs >= base else fetch_range(url, cd_ofs, cd_ofs + cd_size - 1)
    assert len(cd) == cd_size, 'CD fetch short'
    pos, members = 0, []
    while pos < len(cd) - 4 and cd[pos:pos+4] == b'PK\x01\x02':
        (vmade, vneed, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, dsk, iattr, eattr, lho) = struct.unpack('<HHHHHHIIIHHHHHII', cd[pos+4:pos+46])
        name = cd[pos+46:pos+46+nlen].decode('utf8', 'replace')
        extra = cd[pos+46+nlen:pos+46+nlen+elen]
        epos = 0
        while epos + 4 <= len(extra):
            eid, esz = struct.unpack('<HH', extra[epos:epos+4])
            if eid == 0x0001:
                vals, vpos = [], epos + 4
                for cur in (usize, csize, lho):
                    if cur == 0xFFFFFFFF:
                        vals.append(struct.unpack('<Q', extra[vpos:vpos+8])[0]); vpos += 8
                zi = iter(vals)
                if usize == 0xFFFFFFFF: usize = next(zi)
                if csize == 0xFFFFFFFF: csize = next(zi)
                if lho   == 0xFFFFFFFF: lho   = next(zi)
            epos += 4 + esz
        if 'kernelcache' in name:
            members.append((name, method, csize, lho))
        pos += 46 + nlen + elen + clen
    log(f'  kernelcache members: {[(m[0], f"{m[2]/1e6:.0f}MB") for m in members]}')
    assert members, 'no kernelcache member'
    name, method, csize, lho = members[0]
    hdr = fetch_range(url, lho, lho + 30 + 256)
    assert hdr[:4] == b'PK\x03\x04'
    nlen2, elen2 = struct.unpack('<HH', hdr[26:30])
    data_start = lho + 30 + nlen2 + elen2
    comp = fetch_range(url, data_start, data_start + csize - 1)
    assert len(comp) == csize, 'kernelcache fetch short'
    if method == 0:
        raw = comp
    elif method == 8:
        import zlib; raw = zlib.decompress(comp, -15)
    else:
        raise SystemExit(f'zip method {method}')
    open(out_path, 'wb').write(raw)
    return name, len(raw)

# ─────────────────────── img4 / decompression ───────────────────────
def im4p_payload(img4_path):
    blob = open(img4_path, 'rb').read()
    im4p = blob.find(b'IM4P')
    assert im4p >= 0, 'no IM4P'
    assert blob[im4p+4] == 0x16
    kl = blob[im4p+5]; pos = im4p + 6 + kl
    assert blob[pos] == 0x16
    vl = blob[pos+1]; pos = pos + 2 + vl
    assert blob[pos] == 0x04, hex(blob[pos])
    if blob[pos+1] & 0x80:
        nl = blob[pos+1] & 0x7f
        plen = int.from_bytes(blob[pos+2:pos+2+nl], 'big'); pos = pos + 2 + nl
    else:
        plen = blob[pos+1]; pos = pos + 2
    return blob[pos:pos+plen]

def apple_lzss_decode(data):
    # Apple complzss: magic(8) 'complzss' + uncompressed size(4 BE) + compressed size? header 16B total
    assert data[:8] == b'complzss'
    out_size = struct.unpack('>I', data[8:12])[0]
    src, dst = bytearray(data[16:]), bytearray()
    i = 0; flags = 0; mask = 0
    while len(dst) < out_size:
        mask >>= 1
        if mask == 0:
            flags = src[i]; i += 1; mask = 0x80
        if flags & mask:
            p = (src[i] << 8) | src[i+1]; i += 2
            ln = (p >> 12) + 3; off = p & 0xFFF
            for _ in range(ln):
                dst.append(dst[-off - 1])
        else:
            dst.append(src[i]); i += 1
    return bytes(dst[:out_size])

def decompress_kernelcache(img4_path, out_path):
    data = im4p_payload(img4_path)
    magic = data[:4]
    log(f'  payload magic {magic!r} size {len(data)/1e6:.1f} MB')
    if magic in (b'bvx1', b'bvx2', b'bvxn', b'bvx$'):
        tmp_in, tmp_out = out_path + '.lzfse', out_path
        open(tmp_in, 'wb').write(data)
        r = subprocess.run([LZFSE_BIN, '-decode', '-i', tmp_in, '-o', tmp_out],
                           capture_output=True, text=True)
        os.remove(tmp_in)
        assert r.returncode == 0, f'lzfse failed: {r.stderr[:400]}'
    elif data[:8] == b'complzss':
        open(out_path, 'wb').write(apple_lzss_decode(data))
    elif magic == b'krnl' or magic[:4] == b'\xca\xfe\xba\xbe' or magic[:4] == b'\xcf\xfa\xed\xfe':
        open(out_path, 'wb').write(data)
    else:
        raise SystemExit(f'unknown kernelcache compression {magic!r}')
    return os.path.getsize(out_path)

# ─────────────────────────── Mach-O parse ───────────────────────────
LC_FILESET_ENTRY = 0x80000035  # (0x35 | LC_REQ_DYLD)

def find_fileset_entry(raw, base, entry_id):
    """Return the file offset of the embedded Mach-O whose entry_id matches."""
    m = raw.find(b'\xcf\xfa\xed\xfe', base, base + 0x1000)
    if m < 0:
        return None
    ncmds = struct.unpack_from('<I', raw, m + 16)[0]
    off = m + 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from('<II', raw, off)
        if cmd == LC_FILESET_ENTRY:
            # struct fileset_entry_command: cmd, cmdsize, vmaddr(8), fileoff(8),
            # entry_id.offset(4, lc_str relative to cmd start), reserved
            fileoff = struct.unpack_from('<Q', raw, off + 16)[0]
            idofs = struct.unpack_from('<I', raw, off + 24)[0]
            idbuf = raw[off+idofs: off+idofs+256]
            eid = idbuf.split(b'\x00', 1)[0].decode(errors='replace')
            if eid == entry_id:
                return fileoff
        off += cs
    return None

def parse_kernel_macho(raw, base=0):
    m = raw.find(b'\xcf\xfa\xed\xfe', base, base + 0x1000)
    assert m >= 0, 'MH_MAGIC_64 not found'
    KOFF = m
    stub = raw[:m]
    ncmds = struct.unpack_from('<I', raw, KOFF + 16)[0]
    segs, sections = [], []
    off = KOFF + 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from('<II', raw, off)
        if cmd == 0x19:
            nm = raw[off+8:off+24].rstrip(b'\0').decode(errors='replace')
            va, vsz, fo, fsz = struct.unpack_from('<QQQQ', raw, off+24)
            segs.append((nm, va, vsz, fo, fsz))
            if cs > 72:
                nsects = struct.unpack_from('<I', raw, off+64)[0]
                so = off + 72
                for _ in range(nsects):
                    sn = raw[so:so+16].rstrip(b'\0').decode(errors='replace')
                    ss = raw[so+16:so+32].rstrip(b'\0').decode(errors='replace')
                    sa, ssz = struct.unpack_from('<QQ', raw, so+32)
                    sfo = struct.unpack_from('<I', raw, so+48)[0]  # offset is uint32!
                    if ssz: sections.append((sn, ss, sa, ssz, sfo))
                    so += 80
        off += cs
    file_segs = [s for s in segs if s[4] > 0 and s[2] > 0]
    # staticBase must match the convention the app + ClearSword use: the
    # vmaddr of the kernel's own __TEXT segment (kfd ARM64_LINK_ADDR for
    # <=16: 0xfffffff007004000; 17+: 0xfffffe0007004000). The kernelcache is
    # PRELINKED, so min-vmaddr (prelink/kext region) is NOT the kernel base.
    text = [s for s in segs if s[0] == '__TEXT']
    assert text, 'no __TEXT segment'
    static_base = text[0][1]
    return dict(koff=KOFF, stub=stub, segs=segs, sections=sections,
                static_base=static_base, min_va=min(s[1] for s in file_segs))

# ── method A (proc0 list-head signature) is IMPOSSIBLE offline: allproc is
# zero-initialized (__common/BSS) in the kernelcache file - the list is only
# populated at boot. Kept for future live-dump analysis (not called here).
# ─────────────────── method B: XPF shutdownwait port ───────────────────
def find_allproc_signature(raw, info):
    segs, base = info['segs'], info['static_base']
    KOFF = info['koff']
    HI = base + 0x8000000  # generous kernel image span

    def va2file(va):
        for nm, va0, vsz, fo, fsz in segs:
            if va0 <= va < va0 + vsz and fsz:
                return KOFF + fo + (va - va0)
        return None

    try:
        import numpy as np
        use_np = True
    except ImportError:
        use_np = False
    log(f'  signature scan (numpy={use_np})')

    for pid_off in PID_OFF_CANDIDATES:
        found = []
        for nm, va0, vsz, fo, fsz in segs:
            if fsz == 0 or '__TEXT' in nm or 'LINKEDIT' in nm:
                continue
            data = raw[KOFF + fo: KOFF + fo + fsz]
            cands = []
            if use_np:
                import numpy as np
                n = len(data) // 8
                arr = np.frombuffer(data[:n*8], dtype='<u8')
                idxs = np.nonzero((arr >= base) & (arr < HI))[0]
                for i in idxs:
                    cands.append((va0 + int(i) * 8, int(arr[i])))
            else:
                for a in range(0, len(data) - 0x400, 8):
                    V = struct.unpack_from('<Q', data, a)[0]
                    if base <= V < HI:
                        cands.append((va0 + a, V))
            for container_va, V in cands:
                g = va2file(V)
                if g is None or g + pid_off + 8 > len(raw): continue
                if struct.unpack_from('<I', raw, g + pid_off)[0] != 0: continue
                if struct.unpack_from('<Q', raw, g + 8)[0] != container_va: continue  # le_prev -> &allproc
                n = struct.unpack_from('<Q', raw, g)[0]
                gn = va2file(n)
                if gn is None or gn + pid_off + 8 > len(raw): continue
                if struct.unpack_from('<I', raw, gn + pid_off)[0] != 1: continue
                n2 = struct.unpack_from('<Q', raw, gn)[0]
                g2 = va2file(n2) if n2 else None
                if n2 and (g2 is None or struct.unpack_from('<I', raw, g2 + pid_off)[0] < 1): continue
                found.append(container_va)
        if len(found) == 1:
            return found[0], pid_off, 'signature'
        if len(found) > 1:
            log(f'  pid_off {hex(pid_off)}: {len(found)} ambiguous matches')
    return None, None, 'signature'

# ─────────────────── method B: XPF shutdownwait port ───────────────────
def find_allproc_xpf(raw, info):
    KOFF = info['koff']
    A = raw.find(b'shutdownwait\x00')
    if A < 0:
        return []
    str_va = None
    for sn, ss, sa, ssz, sfo in info['sections']:
        if not (ss and sfo): continue
        lo, hi = KOFF + sfo, KOFF + sfo + ssz
        if lo <= A < hi:
            str_va = sa + (A - lo); break
    if str_va is None:
        # many kernelcaches do not enumerate string sections - fall back to
        # segment-level VA computation
        for nm, va0, vsz, fo, fsz in info['segs']:
            if not fsz: continue
            lo, hi = KOFF + fo, KOFF + fo + fsz
            if lo <= A < hi:
                str_va = va0 + (A - lo)
                log(f'  str_va via segment {nm}: {hex(str_va)}')
                break
    if str_va is None:
        return []
    text = [s for s in info['segs'] if s[0] == '__TEXT_EXEC']
    if not text:
        return []
    tva, tfo, tfsz = text[0][1], text[0][3], text[0][4]
    n = tfsz // 4
    insns = struct.unpack_from(f'<{n}I', raw, KOFF + tfo)

    def dec_adrp(insn, pc):
        if (insn & 0x9F000000) != 0x90000000: return None
        rd = insn & 0x1F
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        return (rd, ((pc >> 12) << 12) + (imm << 12))
    def dec_add(insn):
        if (insn & 0xFF800000) != 0x91000000 or (insn >> 22) & 1: return None
        return ((insn & 0x1F), (insn >> 5) & 0x1F, (insn >> 10) & 0xFFF)
    def dec_ldrstr_u(insn):
        if (insn & 0xFFC00000) not in (0xF9400000, 0xF9000000): return None
        return (((insn >> 10) & 0xFFF) * 8, (insn >> 5) & 0x1F,
                'ldr' if (insn & 0xFFC00000) == 0xF9400000 else 'str')

    sites, adrp_at = [], {}
    for idx in range(n):
        insn = insns[idx]
        a = dec_adrp(insn, tva + idx * 4)
        if a:
            adrp_at[a[0]] = (idx, a[1]); continue
        b = dec_add(insn)
        if b:
            rd, rn, o = b
            if rn in adrp_at and idx - adrp_at[rn][0] <= 4 and adrp_at[rn][1] + o == str_va:
                sites.append(idx)
    # 2.-4. per site: XPF procedure - ensure x3, first u64 ldr, resolve adrp(+add) ref
    def mov_to_x3(insn):
        # orr x3, xzr, Xm   (mov x3, Xm)
        if (insn & 0xFFE0FFE0) != 0xAA2003E0 or (insn & 0x1F) != 3:
            return None
        return (insn >> 16) & 0x1F
    def dec_b(insn, pc):
        if (insn & 0xFC000000) != 0x14000000: return None
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        return pc + imm26 * 4

    results = []
    for site in sites:
        rd, _, _ = dec_add(insns[site])
        before_ldr = site
        if rd != 3:
            # XPF: advance until "mov x3, <target>", following unconditional b
            cur = site
            for _ in range(200):
                if cur < 0 or cur >= n: break
                insn = insns[cur]
                m = mov_to_x3(insn)
                if m is not None and m == rd:
                    before_ldr = cur; break
                bt = dec_b(insn, tva + cur * 4)
                if bt is not None and tva <= bt < tva + tfsz:
                    cur = (bt - tva) // 4
                    continue
                cur += 1
        # first unsigned 64-bit ldr/str within 20 insns
        ldr_idx = None
        for j in range(before_ldr, min(before_ldr + 20, n)):
            if dec_ldrstr_u(insns[j]):
                ldr_idx = j; break
        if ldr_idx is None: continue
        o, rn, _kind = dec_ldrstr_u(insns[ldr_idx])
        # resolve adrp feeding rn; honor an "add rn,rn,#imm" chain in between
        base, addoff = None, 0
        for k in range(ldr_idx - 1, max(ldr_idx - 8, -1), -1):
            a = dec_adrp(insns[k], tva + k * 4)
            if a and a[0] == rn:
                base = a[1]; break
            c = dec_add(insns[k])
            if c and c[0] == rn and c[1] == rn:
                addoff += c[2]
        if base is None: continue
        results.append(base + addoff + o)
    return results

# ─────────────────────────── DB handling ───────────────────────────
def load_db():
    if os.path.exists(DB_PATH):
        return json.load(open(DB_PATH))
    return {"entries": []}

def save_db(db):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    json.dump(db, open(DB_PATH, 'w'), indent=2)

def process_build(device, firmware, keep=False):
    os.makedirs(WORK, exist_ok=True)
    free = shutil.disk_usage(BASE).free
    assert free > MIN_FREE_DISK, f'low disk: {free}'
    build = firmware['buildid']
    tag = f'{build}_{device.replace(",", "_")}'
    img4 = os.path.join(WORK, tag + '.img4')
    dec  = os.path.join(WORK, tag + '_dec.bin')
    log(f'== {device} iOS {firmware["version"]} ({build}) ==')

    member_name, sz = fetch_kernelcache_member(firmware['url'], img4)
    log(f'  {member_name}: {sz/1e6:.1f} MB')
    soc = member_name.rsplit('.', 1)[-1] if '.' in member_name else 'unknown'
    sz2 = decompress_kernelcache(img4, dec)
    log(f'  decompressed: {sz2/1e6:.1f} MB')

    raw = open(dec, 'rb').read()
    info = parse_kernel_macho(raw)
    # iOS 17+ kernelcaches are FILESET Mach-Os: the kernel proper is the
    # embedded "com.apple.kernel" entry with full section headers. XPF runs
    # against that entry (cf. XPF xpf_pfsec_init("com.apple.kernel", ...));
    # iOS <=16 kernelcaches are a single prelinked Mach-O (no fileset).
    fs_off = find_fileset_entry(raw, info['koff'], 'com.apple.kernel')
    if fs_off is not None:
        inner = parse_kernel_macho(raw, fs_off)
        log(f'  fileset com.apple.kernel @ {hex(fs_off)}: '
            f'staticBase={hex(inner["static_base"])} segs={len(inner["segs"])} '
            f'sections={len(inner["sections"])}')
        xinfo = inner
    else:
        log(f'  no fileset (pre-iOS-17 layout)')
        xinfo = info
    log(f'  container: stub={info["stub"][:4].hex()} '
        f'staticBase={hex(info["static_base"])} segs={len(info["segs"])}')

    t0 = time.time()
    xpf_targets = find_allproc_xpf(raw, xinfo)
    log(f'  method (shutdownwait xpf): sites resolved {[hex(x) for x in xpf_targets]} '
        f'({time.time()-t0:.1f}s)')
    assert xpf_targets, 'no allproc xref resolutions'
    # XPF uses the FIRST xref; later sites can resolve unrelated loads. Keep
    # only resolutions inside a writable data SEGMENT (many kernelcaches do
    # not enumerate __DATA sections at all, so check segment level).
    def seg_of(va):
        for nm, va0, vsz, fo, fsz in xinfo['segs']:
            if va0 <= va < va0 + vsz:
                return nm
        return None
    valid = []
    for t in xpf_targets:
        sg = seg_of(t)
        if sg and '__DATA' in sg and all(t != v for v, _ in valid):
            valid.append((t, sg))
    assert valid, (f'allproc candidates rejected: '
                   f'{[(hex(t), seg_of(t)) for t in xpf_targets]}')
    entry_va, allproc_sect = valid[0]
    agreement = len(xpf_targets) > 1 and all(t == entry_va for t in xpf_targets[1:])
    method = (f'xpf(shutdownwait) site#{xpf_targets.index(entry_va) + 1} '
              f'segment={allproc_sect} agree={agreement}')
    offset = entry_va - xinfo['static_base']

    db = load_db()
    db['entries'] = [e for e in db['entries']
                     if not (e['build'] == build and e['soc'] == soc)]
    db['entries'].append(dict(
        build=build, ios_version=firmware['version'], device=device, soc=soc,
        kernelcache=member_name, static_base=xinfo['static_base'],
        allproc_va=entry_va, allproc_offset=offset,
        allproc_segment=allproc_sect, method=method,
        xpf_sites=len(xpf_targets), methods_agree=agreement,
        ipsw_url=firmware['url'], derived_at=time.strftime('%Y-%m-%d')))
    save_db(db)
    log(f'  => {build}/{soc}: staticBase={hex(xinfo["static_base"])} '
        f'allproc_offset={hex(offset)} [{method}]')

    if not keep:
        os.remove(img4); os.remove(dec)
    return db

# ─────────────────────────── main ───────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device'); ap.add_argument('--version')
    ap.add_argument('--matrix', action='store_true')
    ap.add_argument('--keep', action='store_true')
    args = ap.parse_args()

    jobs = []
    if args.matrix:
        for dev_id, ver in MATRIX:
            dev = device_json(dev_id)
            fw = pick_firmware(dev, ver)
            if fw:
                db = load_db()
                cur = [e for e in db['entries']
                       if e['device'] == dev_id and e['ios_version'] == fw['version']]
                if cur:
                    log(f'== {dev_id} {fw["version"]}: already in DB, skip')
                    continue
                jobs.append((dev_id, fw))
            else:
                log(f'!! no firmware {ver}.x for {dev_id}')
    elif args.device:
        dev = device_json(args.device)
        fw = pick_firmware(dev, args.version)
        assert fw, f'no firmware {args.version} for {args.device}'
        jobs.append((args.device, fw))
    else:
        ap.error('need --matrix or --device/--version')

    for dev_id, fw in jobs:
        process_build(dev_id, fw, keep=args.keep)

if __name__ == '__main__':
    main()
