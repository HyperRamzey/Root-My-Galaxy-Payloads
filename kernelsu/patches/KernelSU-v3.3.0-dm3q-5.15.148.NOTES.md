# KernelSU delta for dm3q-S918WVLS6CYB3 — v3.3.0 record (no patch file)

Target: SM-S918W, kernel `5.15.148-android13-8-29539737-abS918WVLS6CYB3`
(Samsung android13-5.15 branch). KSU base: v3.3.0 / KSU_VERSION 32601.
Base patch: `kernelsu/patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch`
(applied unmodified).

## Result: zero dm3q-specific hunks

The v3.2.5-era dm3q delta (2 hunks, formerly
`KernelSU-v3.2.5-dm3q-5.15.148.patch`, deleted) is fully subsumed by the
v3.3.0 base. No dm3q patch file ships.

### Former hunk 1 — `enum ucount_type` (5.15 Samsung)

Samsung android13-5.15 names the ucounts limit enum `enum ucount_type`.
The v3.3.0 base already uses it unconditionally:

- `KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch:213-214` —
  `inc_rlimit_ucounts_t` / `dec_rlimit_ucounts_t` take
  `enum ucount_type`. Matches the target BTF (`ucount_type` present,
  `rlimit_type` absent). No delta.

### Former hunk 2 — resolve `sys_call_table` before the RKP early return

The dm2q-fzg1 ordering bug (RKP early return before the table resolve left
the table NULL, so `samsung_sucompat_hook_init()` bailed with `-ENOENT`
and `su_compat` stayed NOT_SUPPORTED) is corrected in the v3.3.0 base:
`ksu_syscall_hook_init()` resolves the table at function top, then hits
the RKP early return at
`KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch:867-871`
(`RKP build: syscall table patch is off`, `ksu_dispatcher_nr = -1`).
Expected dmesg markers after load (unchanged):

```text
KernelSU: sys_call_table=0xffffffc009d1ed10
KernelSU: hook_manager: Samsung sucompat kprobes registered
```

## Outstanding: pair rebuild + on-device re-verify

The committed `android13-5.15.148_kernelsu-dm3q-S918WVLS6CYB3-kdp.ko` /
`ksud-dm3q-S918WVLS6CYB3-kdp` pair (4,629,456 B) was built from the v3.2.5
tree. It must be rebuilt from v3.3.0 (KSU_VERSION 32601) with:

```sh
CONFIG_KSU=m \
CONFIG_KSU_SAMSUNG_KDP=y \
CONFIG_KSU_SAMSUNG_RKP=y \
CONFIG_KSU_SAMSUNG_DEFEX=y \
CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
  <kernel-tree build, ARCH=arm64 LLVM=1, exact release
   5.15.148-android13-8-29539737-abS918WVLS6CYB3>
```

Then: `check_symbol` vs the recovered `vmlinux.elf`, `modinfo` vermagic,
strip debug sections, re-verify `su_compat ENABLED` on hardware, and
re-check the Manager/driver pairing against the mainline manager
(currently validated only against the 32525 manager). Until then the feed
`notes` carries the Manager version caveat.

## History pointers (records removed by the Fold5-only reduction)

- The v3.2.5 patch series: `git log --diff-filter=D -- kernelsu/patches/`
  (reduction commit `39d9995`); v3.2.5 sources survive at tag/commit
  `17c7040`.
- Sibling records referenced by earlier drafts (`dm2q-S916U1UES6CYB3`,
  `dm1q-android13-5.15`): `git log --diff-filter=D -- docs/`.
