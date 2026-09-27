# Support feed schema

`targets-v3.json` keeps one entry for each shared exploit and KernelSU payload.
Automatic selection matches the exact device model and three-part kernel
version, such as `6.6.98`.

Each entry contains only:

- `payloadId` and `displayName`;
- one or more exact `Build.MODEL` values in `models`;
- one or more versions in `kernelVersions`;
- `url` and `size` for the exploit and KernelSU artifacts.

An entry may additionally set `requiresFreshP0Session` to `true` when slide
discovery and exploitation must run in the same payload process. The app then
disables its per-boot P0 cache for that profile and gives the single combined
attempt the target-specific long timeout. The field defaults to `false`, so
existing profiles retain the cached multi-attempt behavior.

The app extracts the leading numeric version from `uname -r`. Kernel suffixes,
Android build displays, fingerprints, and security-patch dates do not
participate in matching.

## Schema history

`targets-v2.json` is gone. The app has read schema v3 only since `v0.2.10`
(`PayloadRepository.kt` pins `support/targets-v3.json`, `SupportManifest.kt`
does `require(schemaVersion == 3)`), and the root helper's self-update fetches
the same v3 URL (`RMG_FEED_URL` in `src/su_daemon.c`). The v2 file this repo
carried was never read by any client of this fork — the pre-v3 clients fetched
`targets-v2.json` from `BuSung-dev`, not from here — so it was removed on
2026-09-27 rather than trimmed.
