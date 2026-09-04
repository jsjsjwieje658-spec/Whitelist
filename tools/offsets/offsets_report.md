# Whitelist allproc offsets DB - multi-iOS pipeline report

Generated: 2026-09-04 18:41 | pipeline: scripts/build_offsets_db.py

## Verified entries (offline XPF + multi-site agreement)

| build | iOS | device | kernelcache | staticBase (file) | allproc VA | offset |
|---|---|---|---|---|---|---|
| 20G81 | 16.6.1 | iPhone12,1 | kernelcache.release.iphone12b | `0xfffffff00700c000` | `0xfffffff00a493640` | `0x3487640` |
| 20G81 | 16.6.1 | iPhone13,2 | kernelcache.release.iphone13 | `0xfffffff007004000` | `0xfffffff00a503670` | `0x34ff670` |
| 20H392 | 16.7.16 | iPhone10,5 | kernelcache.release.iphone10 | `0xfffffff007004000` | `0xfffffff0078b7728` | `0x8b3728` |
| 21A360 | 17.0.3 | iPhone14,2 | kernelcache.release.iphone14 | `0xfffffff02700c000` | `0xfffffff02a2b5308` | `0x32a9308` |
| 21H16 | 17.7 | iPhone13,2 | kernelcache.release.iphone13 | `0xfffffff00700c000` | `0xfffffff00a38ae00` | `0x337ee00` |
| 21H16 | 17.7 | iPhone14,2 | kernelcache.release.iphone14 | `0xfffffff00700c000` | `0xfffffff00a3750a0` | `0x33690a0` |

Same-build/different-SoC pairs (20G81, 21H16) demonstrate that the lookup
key MUST be (build, kernelcache-suffix) - offsets differ per kernelcache.

## iOS 18.x / 26.x status

Tested: 18.0.1/18.1.1/18.2.1/18.3.2/18.4.1/18.5 (22A3370..22F76, t8140),
18.6.2 (22G100, t8140), 26.6.1 (23G83, A18 Pro).

The XPF shutdownwait heuristic no longer applies: starting with xnu 11215
(iOS 18.0) the kernel no longer dereferences allproc inside the
panic("shutdownwait") function - the proc walk moved into proc_iterate,
and the offline signature has no unique anchor. No allproc constant is
shipped for 18+/26; the app handles this gracefully
(wl_allproc_addr() returns 0 -> unsandbox unavailable), which is consistent
with the app gating unsandbox off on iOS 17+ anyway (proc_ro/PPL).
Kernel r/w on 18/26 is unaffected (ClearSword does not need allproc).

## Runtime contract (app side)

1. kern.osversion + hw.machine -> kernelcache suffix -> s_build_symbols entry.
2. allproc = kernel_base + offset (staticBase cancels via slide).
3. Live validation BEFORE first use (read-only): allproc.lh_first -> proc0,
   proc0.le_prev == &allproc, proc0.p_pid == 0, next.p_pid == 1 (launchd).
   Any mismatch -> return 0, no kernel write ever happens.
