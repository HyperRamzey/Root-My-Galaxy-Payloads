# Samsung KernelSU late-load builds

The files in this directory are built from KernelSU `v3.3.0`, commit
`932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e`. They are not interchangeable
between KMIs.

## Versioned artifacts

| File | Target | KMI | Purpose |
| --- | --- | --- | --- |
| `android13-5.15.189_kernelsu-f946b-F946BXXS7GZE5.ko` | `SM-F946B` `F946BXXS7GZE5` | `android13-5.15` | Exact Fold5 module with target `vermagic`, audited for manual relocation; cred `0x798` / `real_cred` `0x790` |
| `ksud-f946b-F946BXXS7GZE5-kdp` | Same exact Fold5 build | `android13-5.15` | Late-load binary embedding the Fold5 5.15 module (SVE-free, 5465448 bytes) |

**All other target pairs (S25U/A56/A36/E3Q/E2S/S921N/S921B/S916B/S9180/
android12-5.10/android14-6.1-generic) were removed on 2026-08-29.** Every one
of those `ksud-*` binaries was rebuilt in the same `-C target-cpu=cortex-a715`
pass as the f946b build that SIGILLed on device: they all carry the identical
SVE codegen signature (4×`CNTH X8`, 38×`PTRUE P0.D`, 26×`PTRUE P0.S`) that
kills any Samsung user-space lacking HWCAP `sve` — i.e. every current Samsung
target. Rebuilt SVE-free replacements must follow
`docs/REBASE-REBUILD-GUIDE.md` §2.2 (generic `-C target-feature=+crc` codegen,
embedded module named after the **KMI**, e.g. `android14-6.1_kernelsu.ko`)
before a target may re-enter the feed.

The standalone `.ko` files are retained for auditing. Root My Galaxy downloads
the corresponding `ksud-*` file because `ksud late-load` loads its embedded
`<kmi>_kernelsu.ko` asset — the embedded name must match the KMI string
derived from uname (e.g. `5.15.189-android13-8-...` → `android13-5.15`), not
the full kernel release.

## Why the stock module crashes on Samsung

The original S25U failure was captured in
`ksu_mark_running_process_locked+0x154`: a generic inline `put_cred()` wrote
directly to a KDP-protected credential reference count. Samsung's kernel uses
`kdp_usecount_inc_not_zero()` and `kdp_usecount_dec_and_test()` for those
objects; bypassing that path caused a synchronous external abort.

Three other Samsung-specific conflicts were confirmed during the 6.6 port:

1. RKP rejected KernelSU's write to an unused syscall-table slot. The generic
   code nevertheless treated the dispatcher as installed, which redirected
   marked syscalls to the unchanged `ni_syscall` entry.
2. DEFEX retained its own task credential tuple. A KernelSU UID transition
   without synchronizing that tuple triggered credential violations, while
   Safeplace/Immutable-root killed KSU-domain helpers.
3. Late-load could not write a new `/data/adb/ksud` after the module changed the
   loader's security context. The failed destination remained a zero-byte file.

## Patch contents

[`patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch`](patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch)
contains the complete source delta from the tagged v3.3.0 tree:

- resolve Samsung KDP credential helpers and release protected credentials with
  `kdp_usecount_dec_and_test()` plus `__put_cred()`;
- install KDP credentials through `prepare_ro_creds()` on a root workqueue and
  update the target task with the firmware-native `kdp_assign_pgd()` path;
- synchronize the DEFEX task credential record after a successful transition;
- limit the DEFEX allow path to the current UID-0 task already in `u:r:ksu:s0`;
- record a syscall-table hook only if the RKP-protected write succeeds;
- when the dispatcher is unavailable, preserve Manager FD delivery with a
  `__arm64_sys_setresuid` kretprobe and provide sucompat through address-based
  syscall kprobes without modifying the syscall table;
- mark nested sucompat calls so a handler invoking the original syscall cannot
  recursively enter the same kprobe;
- stage `ksud` at `/data/local/tmp/.ksud-stage`, rename it onto the same
  `/data` filesystem before loading the module, then finish labels/assets after
  the module is active.

## Rebuild (f946b — the device-verified reference build)

Apply the patch to a clean v3.3.0 checkout:

```sh
git checkout v3.3.0
git apply KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch
```

Kernel module (Windows host, DDK `ghcr.io/ylarod/ddk-min:android13-5.15`):

```sh
make -C /opt/ddk/kdir/android13-5.15 M=/tmp/ksu/kernel ARCH=arm64 LLVM=1 LLVM_IAS=1 \
  CONFIG_KSU=m CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y \
  CONFIG_KSU_SAMSUNG_DEFEX=y CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
  KSU_VERSION=32601 modules
```

Patch the DDK's generated `UTS_RELEASE` / `kernel.release` to the exact
`5.15.189-android13-8-33404244-abF946BXXS7GZE5` first (see
`docs/REBASE-REBUILD-GUIDE.md`). Expected module metadata:

```text
vermagic: 5.15.189-android13-8-33404244-abF946BXXS7GZE5 SMP preempt mod_unload modversions aarch64
scmversion: g932014ab5b2c-dirty
__versions: 0 (manual-relocation loader; audit with kernelsu/tools/audit_module_against_target.py)
```

Then `llvm-strip -d` the module and embed it under its **KMI name**:

```text
userspace/ksud/bin/aarch64/android13-5.15_kernelsu.ko
```

`ksud` (Rust) MUST be built with SVE-free codegen —
`docs/REBASE-REBUILD-GUIDE.md` §2.2 documents the exact environment. The
short version: never pass `-C target-cpu=` for these binaries; use

```powershell
$env:CARGO_PROFILE_RELEASE_LTO="thin"
$env:CARGO_PROFILE_RELEASE_OPT_LEVEL="2"
$env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1"
$env:RUSTFLAGS="-C target-feature=+crc -C link-arg=-Wl,--gc-sections"
cargo build --release --target aarch64-linux-android -p ksud
```

Post-build gate (all three are mandatory):

1. No SVE mnemonics in `.text` (mnemonic sweep in IDA, or scan for the
   tombstone signatures `e8 e3 60 04` / `e0 e3 d8 25` / `e0 e3 98 25`).
2. `python -c "d=open('target/aarch64-linux-android/release/ksud','rb').read(); assert b'android13-5.15_kernelsu.ko' in d"`
3. On-device smoke: `ksud --version`, then a guarded `--late-load` on a
   rooted-but-unactivated kernel; `late-load exit=132` in `ksu-activate.log`
   means SIGILL — the SVE regression is back.

The published f946b pair must always ship together (module + embedding
binary), byte-identical to the committed repo files, with feed sizes matching
`stat()` exactly.
