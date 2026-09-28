# SM-S918W / S918WVLS6CYB3 port — derivation + validation record

Status: **device-tested end-to-end on hardware, 2026-09-18.**

## Environment (2026-09-19)

- Workspace: `E:\s918w-port\` (profile, payload, kernel, tools, notes, evidence).
- WSL2 Ubuntu 26.04 moved to `E:\wsl\Ubuntu` (was C:, freed ~13 GB);
  backup tar `E:\s918w-port\wsl-ubuntu-backup.tar` (12.34 GB). In-WSL paths
  (`/root/...`) unchanged; verified post-move (same `.ko` hash).
- ADB: `C:\Users\Aows\AppData\Local\Temp\opencode\platform-tools\` (kept, ~24 MB).

Canadian Galaxy S23 Ultra (`dm3q`, product `dm3qcsx`) on firmware
`S918WVLS6CYB3` (`UP1A.231005.007.S918WVLS6CYB3`), kernel
`5.15.148-android13-8-29539737-abS918WVLS6CYB3`.

Status: **offline-built 2026-09-18** (build-phase status; superseded by
Device validation below — same boot, hardware run succeeded).

## Firmware identity and acquisition

Samsung FUS, model `SM-S918W`, region `XAC`, via samloader-rs 2.1.0:

```text
S918WVLS6CYB3/S918WOYV6CYB3/S918WVLS6CYB3/S918WVLS6CYB3
```

Device-side ground truth (adb, read-only) matches: `ro.build.PDA`
`S918WVLS6CYB3`, `ril.official_cscver` `S918WOYV6CYB3`, baseband
`S918WVLS6CYB3`, fingerprint
`samsung/dm3qcsx/dm3q:14/UP1A.231005.007/S918WVLS6CYB3:user/release-keys`,
`uname -r` `5.15.148-android13-8-29539737-abS918WVLS6CYB3`.
Bootloader locked, warranty bit 0, verified-boot green.

## Kernel extraction and hashes

AP tar → `boot.img.lz4` → boot image header v4, `kernel_size` u32 at 0x08,
kernel blob at 0x1000:

```text
boot.img size: 100663296
boot.img SHA-256: 0418bd2671ec5d7360a93607b93670e5e51ec248c24a0f4b1ef3355154f9b6ab
kernel size: 45017600
kernel SHA-256: 30fa611c0f878915bfe8556401d901793d0c4543b98d1be321dc0960b1f198a3
```

(Same boot/kernel sizes as the sibling S916U1 CYB3 build — record now in
history, `git log --diff-filter=D -- docs/`; different hash —
different variant, same SoC/base date.)

## Symbol and BTF recovery

`vmlinux-to-elf` 1.3.6 recovered the symbolized ELF at image base
`0xffffffc008000000` (121,160 symbols). A raw-BTF scan found one validated
blob at `[0x20962c4, 0x2629962)` (5,846,686 bytes). A from-scratch Python BTF
parser (full walk: 134,390 types, no desync) supplied all structure layouts.

Notable findings:

- All `.text` symbol offsets match the sibling S916U1 CYB3 build's
  record (same kernel source/compiler/config for core code; record now
  in history, `git log --diff-filter=D -- docs/`).
- Variant-specific `.data` offsets differ and were re-derived:
  `anon_pipe_buf_ops` 0x01d496e0, `ashmem_fops` 0x01ec6a80,
  `kmalloc_caches` 0x01f1d300, `ashmem_misc` 0x02a408b8,
  `"nfnetlink_log"` string 0x01c3dd8e.
- `file_operations` is 0x120 bytes here (36 members: standard 5.15 ops +
  `copy_file_range`/`remap_file_range`/`fadvise` + 4 `android_kabi_reserved`).
  The exploit only uses members through `show_fdinfo` (0xe0), so the shared
  0x110 mirror geometry is unchanged.
- `mm_struct` BTF body is 0x3e0; with `SLAB_HWCACHE_ALIGN` the slab object is
  `ALIGN(0x3e0, 64) = 0x400`, hence `MM_STRUCT_SZ 0x400` (unchanged).
- `P0_KERNEL_PHYS_LOAD 0x80080000` adopted from the same-SoC (SM8550) S23
  family, fail-closed via fingerprint match (Qualcomm BL has no
  load-address literal) — same approach as the sibling port (whose
  sboot-derivation section is now in history, `git log --diff-filter=D
  -- docs/`).

## Tracefs slide anchors

- `SLIDE_TRACEFS_EVENT_ID` = **108**: read live on-device from
  `/sys/kernel/tracing/events/sched/sched_blocked_reason/id`, and confirmed
  offline: `(0x28977c8 − 0x2897508) / 8 = 88`, `20 + 88 = 108`.
- `SLIDE_TRACEFS_WORKER_CALLER_OFF` = `0x0010c9c4` (in `worker_thread`, the
  instruction after the blocking `bl schedule` at `...c9c0`).
- `SLIDE_TRACEFS_VFORK_CALLER_OFF` = `0x000c87a0` (in `wait_for_vfork_done`,
  the return of `bl wait_for_common` at `...879c`).
- Logger oracle triple validated against the image: logger object
  `0x028e1e18` → name `0x01c3dd8e` (`"nfnetlink_log"`); `boot_id` data pointer
  `0x029fe728` → `sysctl_bootid` `0x02c6d429` (pointer value verified equal).

## P0 fingerprint table

`p0_fingerprint.h` generated from the exact raw Image at probe `0x1f0000`
(32 slide rows, 256 source qwords, readback-verified). Row 0 matches the
sibling S916U1 CYB3 build at the same `.text` RVAs (shared core code);
note the probe bases differ (`Image[0x1f0000 - slide]` here vs
`Image[0x400000 - slide]` there), so row 0 is a same-RVA byte comparison,
not a same-probe one. The table was generated fresh regardless and is
bound to this image's SHA-256 above. (Sibling record now in history:
`git log --diff-filter=D -- docs/`.)

## Audit

Procedure (workspace script `tools/audit_target.py`, workspace-local, not
committed): parse all `#define` offsets from `target.h`; check 23 symbols
against the recovered ELF symtab (`kernel/vmlinux.nm` from
`vmlinux-to-elf` 1.3.6 at image base `0xffffffc008000000`, 121,160
symbols), 31 structure layouts against the from-scratch BTF walk
(`kernel/layouts.json`, 134,390 types), plus 1 composite check — 55 total,
0 mismatches.

## Build

Android NDK r28c, `aarch64-linux-android35`, Makefile flags +
`-DSLIDE_STACK_WRITER=1`: `cve-2026-43499-app.so`. Committed r28c
release build (padded era):

```text
size: 104128
SHA-256: cb14959bf64182616f323e59a70aa821bf3b19ba6d696a9800fec6b55718197e
```

Gate removal (upstream `1f00eaa`): the 104,128 truncate target is gone —
no in-tree payload met it (15 of 16 were 123–136 KB). Policy now: build
with `make TARGET=dm3q-S918WVLS6CYB3 ... all` under r30, ship output
as-produced, feed `size` = real `stat()`. r30 build (NDK
30.0.15729638, clang 21):

```text
cve-2026-43499-app.so
  size: 129040
  SHA-256: 51c5b9abff9b5a49f850129ea8bf5d01a69f43a7cb8653d32bb2e88baa58786d
cve-2026-43499 (shell preload, third artifact)
  size: 100496
  SHA-256: f63b6c918e1ebf5698481f859652af9427c654eaf9938c74a1f825ee9e19449c
```

(ELF aarch64, Android 35, NDK r30; warnings pre-existing only. Local r30
root rebuild came out 44,544 B vs the committed 44,520 B — per review
keeping the committed target-independent build, no third variant. CI's
`< 400000` gate is unaffected.)

ELF audit: AArch64 shared object, `NEEDED` only `libdl.so`/`libc.so` (no
`ld-linux-aarch64.so.1` dependency — the issue-#151 bug class is absent),
variant label embedded.

## Kernel source status (2026-09-18, updated)

The exact CYB3 opensource drop is no longer listed: the Samsung portal
keeps only the newest unified S918-family drop (FZE/FZF/FZG-era,
5.15.189; portal id 14018, all S918 variants bundled). Portal file
downloads sit behind hCaptcha, so automated fetching stops here.

Fallback plan (gated, all offline): build the module from the newest
unified S918 tree with the exact dm3q CYB3 `config.gz` and the exact
`5.15.148-android13-8-29539737-abS918WVLS6CYB3` release string. This is
defensible because 5.15.148→5.15.189 are both 5.15.y stable (no API/
prototype churn → export CRCs stable) and Samsung's `android_kabi_reserved`
slots keep existing field offsets stable. Gates before any device contact:

1. Compile-time offset check: `offsetof()` for ~40 critical fields
   (task_struct pi/cred, file_operations ops, page, waiter, mm) from the
   newer headers must equal our BTF values exactly.
2. `audit_module_against_target.py --manual-relocation`: 0 missing, 0 CRC
   mismatches, empty `__versions`.
3. Only then: `ksud` packaging and the Shizuku device test.

KernelSU source prep: v3.3.0 base + samsung patch, applied cleanly.
Decision per review: rebase onto v3.3.0 / KSU_VERSION 32601 (the cleaner
path vs a v3.2.5 waiver). Delta analysis
(`kernelsu/patches/KernelSU-v3.3.0-dm3q-5.15.148.NOTES.md`): **zero
dm3q-specific hunks** — both v3.2.5-era hunks (ucount_type, RKP
resolve-before-return) are subsumed by the v3.3.0 base, so no dm3q patch
file ships. Outstanding: rebuild the KO + ksud pair from v3.3.0 and
re-verify on hardware (see Remaining work). NDK r28c Linux toolchain was
at `/root/ndk/android-ndk-r28c`; r30 required for the artifact rebuilds.
Missing input: the Samsung kernel tree (`E:\s918w-port\oss\`, needs a
manual captcha download).

## KernelSU pair (built 2026-09-18, offline; validated live same day — see
Device validation; v3.3.0 rebuild outstanding, see Remaining work)

- Tree: Samsung unified S918 FZH3-era source (5.15.189) + exact dm3q CYB3
  `config.gz` + exact release override. Layout gate vs target BTF passed
  (32 member + 5 sizeof checks, all byte-identical).
- Compiler: NDK r25c clang 14.0.7 (matches IKCONFIG `r450784e`), LLVM=1,
  `CONFIG_KSU=m` + KDP/RKP/DEFEX + `NO_PATCH_TEXT=y`,
  `KCFLAGS=-DCONFIG_DEBUG_INFO_BTF_MODULES=1`, `KBUILD_MODPOST_WARN=1`.
- Patches: samsung-kdp-rkp-defex + dm3q-5.15.148 (ucount_type; table
  resolved before RKP return so sucompat registers).
- Rebuilt ksud note: upstream Kernel-SU org git deps were deleted
  (adb_client, java-properties, ksu_props, rustix fork). Manifest rewired
  to same-commit homes (5ec1cff/adb_client@d97a9664, ReSukiSU mirrors for
  ksu_props@699849f3 and rustix@4a53fbc, crates.io java-properties 2.0.0);
  cargo git now uses the CLI backend. ksud embeds the KO below as
  `android13-5.15_kernelsu.ko`, version 32525 / 3.2.5.

```text
android13-5.15.148_kernelsu-dm3q-S918WVLS6CYB3-kdp.ko
  size: 357048
  SHA-256: eb7e4b4a4518d130faec24e8203e4a8469096e4ac1d4c0432cdf4f355d8189bf
  vermagic: 5.15.148-android13-8-29539737-abS918WVLS6CYB3 SMP preempt mod_unload modversions aarch64
  audit: 200 undefined imports, 0 missing, 65 via kallsyms, 0 CRC mismatches, __versions empty

ksud-dm3q-S918WVLS6CYB3-kdp
  size: 4629456
  SHA-256: d972cd679209c864433c85f4c13dde80c36e9bdd15b8826d360a45c148f76a78
```

## Device validation (2026-09-18, SM-S918W S918WVLS6CYB3, first hardware run)

- Exploit (4x pile-up build `cb14959b`): slide/KASLR OK every attempt;
  full 32-object group on attempt 2; `uid=2000->0`, `root=1`, no panic,
  Knox warranty bit 0. Log: `test-attempt2.log` (prior run), phone-side
  `dm3q-attempt3.log`.
- KernelSU late-load: `kernelsu ... Live` in `/proc/modules`, no panic.
  ksud stages complete (`ephemeral: true`, KMI `android13-5.15` detected,
  entered `u:r:ksu:s0`). Defeated two integration bugs found live: ksud
  needed a new `--ephemeral` flag (added), and DEFEX Safeplace kills any
  ksud exec parented by `sh` (guarded logcat bind-mount path required;
  direct exec gets SIGKILL + Safeplace violation in dmesg).
- Manager v3.2.5 (32525-2): `Working <LKM> [Jailbreak mode]`, kernel
  `5.15.148-android13-8-29539737-abS918WVLS6CYB3`, fingerprint
  `samsung/dm3qcsx/...`, SELinux Enforcing. Screenshot:
  `SM-S918W-S918WVLS6CYB3-KernelSU-manager.png`.
- Control ioctl from an unprivileged probe: version=32525 flags=0x5
  features=0x5 uapi=2, **`su_compat=ENABLED`** — the table-before-RKP
  fix verified live.
- Pending: app-facing `su` grant (Termux shows no su until Manager
  allowlists it; Superuser count 0 at validation time).

## Validation evidence (all 2026-09-18, same boot, no reboot since)

- `test-attempt2.log`: prior run — slide 3/3, mm-search 0-3 collisions,
  fail-clean, no panic.
- `dm3q-attempt3.log` (phone + workspace copy pending): build `cb14959b`
  — slide OK all 8 attempts, 32/32 group on attempt 2, `uid=2000->0
  root=1`, no panic, Knox 0. Runs are distinguished by artifact hash;
  `S918_MM_PILEUP_FUTEXES` (`target.h:137`, 1024) documents the intended
  pile-up count for this configuration but is currently unconsumed (the
  `util.c:453-460` override chain selects
  `SLIDE_KSNITCH_APPENDED_FUTEXES`, 2048). Wiring it in changes exploit
  behaviour and is deferred to the r30 rebuild + device re-validation.
- `SM-S918W-S918WVLS6CYB3-KernelSU-manager.png`: Manager `Working <LKM>
  [Jailbreak mode]`, `32525-2`, exact kernel/fingerprint, Enforcing.
- `SM-S918W-S918WVLS6CYB3-Termux-su.png`: Termux `su` → `#`, `id` →
  `uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0` (after
  Manager grant; pre-grant `su` correctly hidden).
- Unprivileged ioctl probe: version=32525 flags=0x5 features=0x5 uapi=2,
  `su_compat=ENABLED`.
- Third-party apps: Termux granted via Manager prompt, `su` → `uid=0`
  `u:r:ksu:s0` (screenshot). AdAway 6.1.4 granted via Manager Superuser
  profile toggle (its stat-only root check never fires a prompt by itself);
  with grant: 80,173 blocked, 3 sources up-to-date, blocking active
  (screenshot). AFWall+ installs but reports missing iptables targets/
  chains on this kernel and was not pursued (iptables core itself works:
  `iptables -L` and xt_owner confirmed present via root shell).
- Manager downgraded 32601→32525 afterward (matched pair; grants live
  kernel-side and survived).
- Final ksud: 4,629,456 bytes,
  `d972cd679209c864433c85f4c13dde80c36e9bdd15b8826d360a45c148f76a78`
  (adds `--ephemeral`; manifest dep homes rewired with same pins).
- Root helper (current, target-independent, matches in-tree f946b build
  byte-for-byte):
  `ee0a9f1481c998028181b09a32f28885fe01c2a5f3806226208feb3788d0299f`
  (late-load path; `--ephemeral` is a ksud-side flag, present in the
  rebuilt ksud — the helper invokes late-load and the stages report
  `ephemeral: true`, verified live).

## Remaining work

1. ~~App-facing `su` grant~~ DONE (see Validation evidence: Termux `uid=0
   ... u:r:ksu:s0`, AdAway 80,173 blocked).
2. ~~r30 toolchain rebuild~~ DONE for userspace (`app.so` + preload
   above); still outstanding: KSU v3.3.0 pair rebuild (KO + ksud,
   KSU_VERSION 32601) + on-device re-verify + mainline-Manager pairing
   check (validated only against the 32525 manager so far).
3. Commit evidence logs (`test-attempt2.log`, `dm3q-attempt3.log`,
   phone-side copies).
4. App-path validation: re-run exploit → late-load → su through the
   fork app's wireless-ADB shell (uid 2000) with its env block, not
   Shizuku; check pin-gate opens on dm3q.
