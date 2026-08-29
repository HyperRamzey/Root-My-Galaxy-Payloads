# Rebase & Rebuild Guide — KernelSU + Payloads

This is the exact procedure used for `v3.2.5/b0bc817 → v3.3.0/932014a` (`O2+thinLTO+armv8-a+crc+crypto` for all builds).

## 1. Rebase Samsung patches to new KernelSU tag

### 1.1 Fetch both tags

```sh
git clone --depth 1 --branch v3.2.5 https://github.com/tiann/KernelSU.git /tmp/ksu-v3.2.5
git clone --depth 1 --branch v3.3.0 https://github.com/tiann/KernelSU.git /tmp/ksu-v3.3.0
```

### 1.2 Test current patches on new tag

```sh
cd /tmp/ksu-v3.3.0
git apply --check ../../kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch
# expected failures on v3.3.0:
#   kernel/Kbuild:61, kernel/core/init.c:26, userspace/ksud/src/late_load.rs:78,
#   userspace/ksud/src/utils.rs:1, kernel/hook/arm64/patch_memory.c:197
```

### 1.3 Fix the 5 failing files manually (same intent, new context)

Copy the intent from `kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch:1`:

* **`kernel/Kbuild:1`** — add after `kernelsu-objs := core/init.o`:
  `compat/samsung_kdp.o` + `compat/samsung_defex.o`; add `CONFIG_KSU_SAMSUNG_*` `ccflags-y` after `CONFIG_KSU_DEBUG` block (now also `CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER` exists), add `-I$(objtree)/security/selinux`, change `KSU_KERNEL_DIR/include` → `+ -I$(KSU_KERNEL_DIR)/..`, fallback `KSU_VERSION ?= 33000` (was `32525`).
* **`kernel/core/init.c:8`** — add `#include "ksu_samsung_kdp.h"` + `compat/samsung_defex.h`; after `int __init kernelsu_init(void) {` insert `int ret;` and replace `ksu_cred = prepare_creds() / ksu_init_symbol_resolver() / ksu_syscall_hook_init()` block with Samsung `kdp_init() → prepare_creds() → defex_init()` + `ksu_put_cred()`/`kdp_exit/defex_exit` on `kernelsu_exit()` (`src/common.h:837` pattern).
* **`kernel/hook/arm64/patch_memory.c:188`** — guard `ksu_patch_text()` with `#ifdef CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT` → `-EOPNOTSUPP`.
* **`userspace/ksud/src/utils.rs:1`** — add `chown`, `Gid/Uid` imports, split `install(libadbroot, data_path)` → `stage_daemon() + stage_daemon_from("/data/local/tmp/.ksud-stage") + finish_install()` (new `finish_install` does **not** copy `/proc/self/exe`, only `restorecon`+assets).
* **`userspace/ksud/src/late_load.rs:1`** — drop `Command` import, `run(_package_name,…)`, `stage_daemon_from("/data/local/tmp/.ksud-stage")` before `has_kernelsu()`, `finish_install(None,None)`, drop `am force-stop/start` Manager restart.

Use `rebase_kbuild.py` etc. or edit in place, then:

```sh
git diff --stat  # should show the 5 files
```

### 1.4 Apply the other two patches

```sh
git apply --check ../../kernelsu/patches/KernelSU-v3.2.5-samsung-selinux_hide.patch  # uses kprobe when NO_PATCH_TEXT
git apply ../../kernelsu/patches/KernelSU-v3.2.5-samsung-selinux_hide.patch
git apply --check ../../kernelsu/patches/KernelSU-v3.2.5-dm2q-fzg1.patch
# fixup: samsung_kdp.c rlimit_type → ucount_type, syscall_hook.c add RKP early-return
```

### 1.5 Generate the new combined patch

```sh
git add -A
git diff --cached --binary > ../../kernelsu/patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch
# check: 16 files, 1026+59-; includes selinux+dm2q
git apply --check ../../kernelsu/patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch  # on fresh v3.3.0 clone → exit 0
```

### 1.6 Update repo metadata

* `kernelsu/README.md:3` — `v3.3.0 / 932014ab…`, `dist/kernelsu-v3.3.0-src.tar.gz` (`git archive --format=tar.gz --prefix=KernelSU-v3.3.0/ HEAD -o dist/kernelsu-v3.3.0-src.tar.gz` in fresh clone).
* `.github/workflows/ci.yml:113` — `Fetch v3.3.0`, single `git apply` loop for `KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch`.

## 2. Rebuild everything with `O2+thinLTO+armv8-a+crc+crypto`

### 2.1 C payloads (`src/*.c`, `preload.c`, `su_daemon.c`)

`Makefile:9` and `build_f946b.bat:8` already:

```
-O2 -flto=thin -march=armv8-a+crc+crypto -mtune=cortex-a715 -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,-O3
```

```sh
# Windows (PowerShell, NDK 30.0.15729638):
$env:ANDROID_NDK_HOME="C:\...\ndk\30.0.15729638"
# fix mkdir -p on Windows:
New-Item -ItemType Directory -Path build\essi-A566EXXSCCZG6 -Force | Out-Null
make TARGET=f946b-F946BXXS7GZE5 ANDROID_NDK_HOME="$env:ANDROID_NDK_HOME" NDK_HOST=windows-x86_64 API=35
make TARGET=e2s-S926BXXUEDZDR ...
# or for all 17:
Get-ChildItem src/targets | % { make TARGET=$_.Name ... }
# artifacts/<target>/cve-2026-43499* now 136352/107368 etc. (was Oz)
```

### 2.2 Rust `ksud` (v3.3.0, `userspace/ksud`)

Fix `PATH` first (rustup vs Program Files):

```sh
$env:PATH="C:\Users\admin\.cargo\bin;C:\Users\admin\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin;$env:PATH"
$env:KSU_LKM_BOOTSTRAP_CC=".../ndk/.../bin/clang.exe"
$env:ANDROID_NDK_HOME=".../ndk/30.0.15729638"
$env:LIBCLANG_PATH=".../ndk/.../bin"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=".../aarch64-linux-android35-clang.cmd"
$env:CC_aarch64_linux_android=".../aarch64-linux-android35-clang.cmd"
$env:AR_aarch64_linux_android=".../llvm-ar.exe"
# O2+thinLTO+arch for Rust:
$env:CARGO_PROFILE_RELEASE_LTO="thin"
$env:CARGO_PROFILE_RELEASE_OPT_LEVEL="2"
$env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1"
# SVE-free codegen (MANDATORY): Samsung 5.15/6.1/6.6 kernels do NOT expose
# SVE to userspace (HWCAP lacks sve even on the 8 Gen 2 kalama P-cores).
# -C target-cpu=cortex-a715 (ARMv9.1) let LLVM auto-vectorize strsim/clap
# into SVE (CNTH/LD1SB{Z}/PTRUE) -> SIGILL (exit 132) on every ksud exec:
# late-load died and root died with it (same class as the C-payload bugs
# 9be3f6d SVE-addvl / b2044a5 FEAT_MOPS). NEVER pass target-cpu here.
$env:RUSTFLAGS="-C target-feature=+crc -C link-arg=-Wl,--gc-sections"
# bindgen needs sysroot when cross-building:
# patch userspace/ksud/build.rs:44  .clang_args(["-x","c++","-I../../"])
#   → + "--target=aarch64-linux-android", "--sysroot=C:/.../sysroot"
```

Then per-KMI — copy the exact `*.ko` under its **KMI name**. ksud's
late-load resolves the module as `format!("{kmi}_kernelsu.ko")` where KMI
comes from uname (`5.15.189-android13-8-...` -> `android13-5.15`), so the
embedded asset MUST be `android13-5.15_kernelsu.ko`. The f946b rebuild
briefly embedded it as `android13-5.15.189_kernelsu.ko` and every
late-load aborted with "asset not found: android13-5.15_kernelsu.ko":

```sh
Get-ChildItem userspace/ksud/bin/aarch64/*.ko | Remove-Item -Force
Copy-Item G:\...\kernelsu\android13-5.15.189_kernelsu-f946b-F946BXXS7GZE5.ko userspace/ksud/bin/aarch64/android13-5.15_kernelsu.ko
cargo build --release --target aarch64-linux-android -p ksud
Copy-Item target/aarch64-linux-android/release/ksud G:\...\kernelsu/ksud-f946b-F946BXXS7GZE5-kdp
# repeat for e2s (android14-6.1_kernelsu.ko), s25u (android15-6.6_kernelsu.ko), etc. — 12 binaries
# f946b ksud is 5465448 bytes (generic codegen; the A715-tuned build was 5531824 and SIGILLed)
```

`android12-5.10`/`android14-6.1` generic and `A366/A566` `android15-6.6` each need their own `ko → androidXX-Y.Y_kernelsu.ko` copy before `cargo build`.

Post-build sanity (mandatory):

```sh
# 1. No SVE instructions (run a mnemonic sweep in IDA or scan .text).
#    The A715 build faulted at strsim::generic_jaro+52 (tombstone PC 0x3c2c94).
# 2. Embedded asset name == KMI name:
python -c "d=open('target/aarch64-linux-android/release/ksud','rb').read(); assert b'android13-5.15_kernelsu.ko' in d; print('asset ok')"
# 3. On-device smoke (before swapping the repo artifact):
adb push target/.../release/ksud /data/local/tmp/ksud-test && adb shell /data/local/tmp/ksud-test --version
```

### 2.3 Feed & dist

There is no `update_feed.py`; sizes are refreshed the way
`tools/generate_target.py refresh_payload_entry()` does — the kernelsu node's
size MUST equal `stat(kernelsu/ksud-<profile>-kdp)`, exploit/rootHelper
sizes equal the artifacts/ files. Edit both copies with that rule
(support/targets-v3.json + dist/support/targets-v3.json), then sync dist/ as
release.yml does:

```sh
#   dist/<target>/<target>-cve-2026-43499*  from artifacts/<target>/
#   dist/kernelsu/ksud-* + *.ko              from kernelsu/
#   dist/support/targets-v3.json             from support/
```

CI validates: `python -m py_compile tools/generate_target.py` + feed `schemaVersion==3` + URLs pinned to `HyperRamzey/.../main/`.

## 3. Publish

```sh
git add -A
git commit -m "feat(ksu): rebase to v3.3.0; feat: O2+thinLTO rebuild"
git push origin main
git tag -a v1.2.15 -m "v1.2.15: O2+thinLTO"
git push origin v1.2.15  # triggers release.yml → sanity make + publish committed artifacts byte-for-byte
```

## 4. Device hygiene

```sh
adb shell su -c 'rm -rf /data/local/tmp/* /data/local/tmp/.* 2>/dev/null; mkdir -p /data/local/tmp; chown 2000:2000 /data/local/tmp; chmod 0771 /data/local/tmp; restorecon -RF /data/local /data/local/tmp'
# next reboot: RootOnBootService re-stages new O2 ksud/f946b.so from feed (size mismatch ⇒ re-download)
```

Verification: `adb shell su -c id` → `u:r:ksu:s0`, `cat /proc/modules` `kernelsu`, `ksu-keeper.log` `done-this-boot`, `file build/f946b/cve-2026-43499-app.so` `aarch64`.
