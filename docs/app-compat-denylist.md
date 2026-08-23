# App compatibility: Zygisk denylist for anti-cheat titles

## Symptom

Clash Royale (`com.supercell.clashroyale`) aborts during
`InitializationProvider.onCreate` with an obfuscated detection exception:

```
E AndroidRuntime: FATAL EXCEPTION
E AndroidRuntime: lmnoxujmd.ay: 16
```

Reproduces on Fold5 / One UI 8.5 under KernelSU + Zygisk Next 1.4.5.

## Root cause

The **Vector** module (`org.matrix.vector`, LSPosed fork, shipped as
`/data/adb/modules/zygisk_vector`) injects its Zygisk library into every app
process via Zygisk Next. CR's init-time check detects the injection artifact
itself. Disabling all Vector-internal modules does **not** help — the Vector
loader library is still mapped into the process. A per-app umount flag alone
does not help either while Zygisk Next's enforce-denylist switch is off:
ZN then ignores root-manager umount/deny lists entirely.

## Fix

Keep the per-app umount entry (KSU manager → Clash Royale → "Umount
modules") **and** enable ZN's denylist enforcement once per install:

```sh
su -c '/data/adb/ksu/bin/znctl enforce-denylist enabled'
```

Verify:

```sh
su -c '/data/adb/ksu/bin/znctl status'   # expect: enforce_denylist:1
```

The setting persists across reboots (stored in ZN's encrypted context file).
With enforcement on, ZN skips library injection and umounts module mounts for
every denylisted package; other apps are unaffected. Confirmed working: CR
launches and stays alive with Vector + all other modules active.

If `znctl` reports "failed to connect to server" immediately after boot, retry
once zygote finished restarting — the tool talks to the zygiskd socket.
