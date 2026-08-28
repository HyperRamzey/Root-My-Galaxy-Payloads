# Wide Color Gamut enabler — Galaxy Z Fold5 (SM-F946B)

KernelSU module that enables framework **Wide Color Gamut (WCG)** on the
Galaxy Z Fold5 (`SM-F946B`, Snapdragon 8 Gen 2, Android 16 / OneUI 8).

The hardware already supports WCG — Samsung only disables it in software.
This module removes the software block.

## Why Samsung disables it

It is a deliberate software choice, not a hardware limit. Samsung routes color
through its own engine instead of Android's framework color management, and the
WCG Configuration bit is tied to the latter.

`persist.sys.sf.native_mode` is SurfaceFlinger's display-color setting:
`0 = MANAGED` (framework color management), `1 = UNMANAGED` (native). The WCG
bit only turns on in managed mode, and Samsung ships `1`. The reasons:

- **Own color pipeline, not AOSP's.** Display color on One UI comes from MDNIE
  (`SemMdnieManagerService` / `MdnieScenarioControlService` — the consumers of
  the `SEC_FLOATING_FEATURE_LCD_SUPPORT_WIDE_COLOR_GAMUT` flag) and Samsung's
  screen-mode system, not from SurfaceFlinger's color management. Enabling
  framework WCG would hand color control to AOSP and conflict with their tuning.
- **The default look is not a managed wide-gamut mode.** The stock screen mode
  maps to UNMANAGED (`native_mode=1`); the AOSP managed path (`0`) corresponds
  to Natural/Boosted. One UI also overrides the AOSP `display_color_mode` lever
  and keeps forcing UNMANAGED.
- **Consistent, controlled output.** Letting apps opt into wide-gamut rendering
  produces app-to-app color inconsistency, so Samsung keeps the flag off and
  controls the look itself.
- **Exposed their own way.** Users still get wide/punchy color via
  Settings → Screen mode (Vivid/Natural/Photo) and HDR for video — just not via
  the standard `android.hardware.wide_color_gamut` feature flag.

The consequence: apps that query WCG get `false` and render sRGB even though the
panel can show P3. This module flips `native_mode` to managed and declares the
feature, so the framework finally grants the wide gamut the hardware has had all
along — at the cost of moving from Samsung's "Vivid" processing to framework
color management.

## Why WCG is off out of the box

The panel and SurfaceFlinger are Display-P3 capable:

```text
ro.surface_flinger.has_wide_color_display = true
ro.surface_flinger.use_color_management   = true
ro.surface_flinger.has_HDR_display        = true
ColorMode::NATIVE / SRGB / DISPLAY_P3     (both displays)
```

…but the framework reports **no** WCG:

```text
pm has-feature android.hardware.wide_color_gamut  -> false
cmd activity get-config                            -> nowidecg
dumpsys display                                    -> no FLAG_WIDE_COLOR_GAMUT
```

### The gate (verified from this device's `services.jar`)

Samsung's `WindowManagerService.displayReady()` sets
`mHasWideColorGamutSupport` from `ro.surface_flinger.has_wide_color_display`
(true here). `DisplayContent.computeScreenConfiguration()` then computes the
Configuration wide-color bit as:

```java
wideColorGamut = displayInfo.isWideColorGamut()          // DISPLAY_P3 in supportedColorModes -> true
              && mWmService.mHasWideColorGamutSupport     // = has_wide_color_display        -> true
              && SystemProperties.getInt("persist.sys.sf.native_mode", 0) != 1;
```

Samsung ships **`persist.sys.sf.native_mode=1`**, which forces SurfaceFlinger
into unmanaged native color mode and makes the whole expression false — hence
`nowidecg`. That property is the single blocker. Separately, Samsung omits the
`android.hardware.wide_color_gamut` PackageManager feature declaration.

Bytecode evidence (device `services.jar`, containerized DEX):

| Reference | Class / method | Access |
| --- | --- | --- |
| `ro.surface_flinger.has_wide_color_display` | `WindowManagerService.displayReady` | read |
| `persist.sys.sf.native_mode` | `DisplayContent.computeScreenConfiguration` | read (the gate) |
| `persist.sys.sf.native_mode` | `DisplayTransformManager.setDisplayColor` | **write** |
| `persist.sys.sf.native_mode` | `ColorDisplayService.getColorModeInternal` | read |

`SEC_FLOATING_FEATURE_LCD_SUPPORT_WIDE_COLOR_GAMUT` is already `TRUE` in
`floating_feature.xml`, so Samsung's own floating-feature gate is not blocking.

### The runtime reset (verified on-device)

`ColorDisplayService.setUp()` (runs during system_server boot) calls
`onDisplayColorModeChanged(getColorModeInternal())`, which calls
`DisplayTransformManager.setDisplayColor(nativeMode, colorMode)` →
`SystemProperties.set("persist.sys.sf.native_mode", …)`. This is what rewrites
the property back to `1` at every boot.

**A one-shot set is not enough.** On a real boot the plain
`post-fs-data.sh` + `service.sh` re-assertion lost the race: `setUp()` wrote
`1` back and WMS read `1`, leaving `nowidecg`. The AOSP "clean" lever — setting
`Settings.System display_color_mode` to a managed mode — is also a dead end on
One UI: Samsung overrides the color-mode path and `setUp()` still forces
`native_mode=1` (verified: `display_color_mode=0` left `native_mode=1`).

**The fix is a watchdog.** `wcg_watchdog.sh` re-asserts
`persist.sys.sf.native_mode=0` every 0.2 s for the first 300 s of boot, so the
value is back to `0` before `WindowManagerService` reads it during
`computeScreenConfiguration()`. Verified reliable across repeated
system_server restarts on the connected SM-F946B:

```text
reset to stock                 native_mode=1
watchdog running               native_mode=0   (re-asserted within 0.2 s)
zygote / system_server restart native_mode=0   config=widecg   (3/3 trials)
```

A post-boot safety net in `service.sh` additionally checks the Configuration
once the device finishes booting and, only if it is still `nowidecg`, forces a
display recompute with a minimal override-preserving `wm density` blip.

## What the module does

1. **`system.prop` / `post-fs-data.sh`** — set `persist.sys.sf.native_mode=0`
   (via `resetprop`) before SurfaceFlinger and system_server start, and start
   the watchdog that defends the value during the whole boot race.
2. **`wcg_watchdog.sh`** — background loop that re-asserts `native_mode=0`
   every 0.2 s for 300 s, defeating `ColorDisplayService.setUp()`'s reset so
   WMS computes `widecg`. Self-exits after the window; never more than one
   instance runs.
3. **`service.sh`** — re-asserts the property in `late_start`, makes sure the
   watchdog is alive, and schedules the conditional post-boot density-blip
   recompute as a safety net.
4. **`system/etc/permissions/android.hardware.wide_color_gamut.xml`** —
   declares the feature so `pm has-feature` returns true.
5. **`customize.sh`** — refuses to install on non-Fold5 models.
6. **`uninstall.sh`** — stops the watchdog and restores
   `persist.sys.sf.native_mode=1` (stock).

## Install

Flashable zip (KernelSU Manager → Modules → Install), or let the Root-My-Galaxy
activation flow apply it from `/data/adb/modules/wcg_f946b/`.

```sh
# build the zip
python tools/build_wcg_module.py        # -> dist/wcg_f946b/wcg_f946b-v1.1.0.zip
```

Requires KernelSU working (this repo's late-load LKM + activation).

## Verify (after reboot / activation)

```sh
adb shell su -c 'getprop persist.sys.sf.native_mode'            # 0
adb shell pm has-feature android.hardware.wide_color_gamut      # true
adb shell cmd activity get-config | grep -i widecg              # widecg
adb shell dumpsys display | grep -i 'wide\|colorMode'
adb shell cat /data/local/tmp/wcg_f946b.log
```

## Runtime health (verified)

Checked via `logcat`, `dmesg`, and `dumpsys dropbox` after a real boot with the
module active (SM-F946B, OneUI 80500):

- **0 SELinux denials** from the module — the watchdog, `resetprop`, and the
  `surfaceflinger_color_prop` write are all permitted.
- **No errors/warnings** referencing `wcg_f946b`, `wcg_watchdog`,
  `ColorDisplayService`, `DisplayTransformManager`, or SurfaceFlinger color.
- **No log spam** — the watchdog only appends to
  `/data/local/tmp/wcg_f946b.log` and stays silent in logcat.
- **system_server stable** — no crash/ANR attributable to the module.

Unrelated noise you may see that is **not** caused by this module:
`com.qti.snapdragon.qdcm_ff` failing to load a missing
`vendor.display.color.V1_0.IDisplayColor` shared library (a pre-existing
Qualcomm QDCM provisioning gap), and periodic
`E Watchdog: !@Sync … softdog disabled` lines, which are Samsung's routine
30 s system_server diagnostics.

## Notes / caveats

- Enabling WCG hands color management to the framework; the display may look
  different from Samsung's default "Vivid" processing (this is expected).
- Samsung's `ColorDisplayService.setUp()` rewrites `native_mode` to `1` on every
  boot; the bundled watchdog re-asserts `0` for the first 300 s so WMS reads the
  managed value. Changing the screen mode in Settings can also call
  `setDisplayColor()` — if you do that, the watchdog (while active) re-asserts
  `0`. Disable the module if you want to switch screen modes freely.
- `pm has-feature` only flips after a real boot, because the feature XML is
  mounted systemlessly by KernelSU (`mount=true`) and PackageManager scans it at
  boot. The `widecg` Configuration bit is the primary WCG indicator.
- The post-boot density-blip safety net only fires if the Configuration is still
  `nowidecg`; it preserves any existing `wm density` override.
- Revert by uninstalling the module (stops the watchdog, restores
  `native_mode=1`) or `resetprop persist.sys.sf.native_mode 1`.
