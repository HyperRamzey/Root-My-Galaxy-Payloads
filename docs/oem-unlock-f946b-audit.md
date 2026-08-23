# F946BXXS7GZE5 OEM-unlock machinery audit (One UI 8.5 / OS16)

Personal-device security research on owned hardware. Everything below was
gathered **read-only**: IDA static analysis of the shipped ABL plus `dd`
reads of state partitions over root adb. No partition was ever written
(any write risks an unrecoverable img-auth-failed brick on this firmware;
Odin refuses to flash outside maintenance mode).

Method mirrors [keyarr/oems24-audit](https://github.com/keyarr/oems24-audit)
(SM-S928B, same One UI 8.5 generation), cross-checked against
[haroon-ai1/s23u-oem-unlock-research](https://github.com/haroon-ai1/s23u-oem-unlock-research).

## Source material

- `BL_F946BXXS7GZE5_...tar/abl.elf.lz4` -> raw abl image (4,194,324 B,
  sha256 `f69b0b1e196d5c387ccdaa616a25338ac418dd708bdaf09ede46e7ca27a1c671`)
- LinuxLoader ARM64 PE carved with keyarr's `extract_linuxloader.py`
  (GUID `f536d559-459f-48fa-8bbc-43b554ecae8d`, 2,146,304 B, sha256
  `6b5eed14d972515057623977449d803eb5ca4c005e5fa1b2800213f43837131c`)
- Live partitions: `devinfo` 4 KiB, `steady` first 4 MiB, `em` 2 MiB

## ABL findings (IDA, linuxloader PE)

All six S24U markers present (`IsUnlocked`, `IsUnlockCritical`,
`GetUnlockCount`, `Device is unlocked`, `Skipping boot verification`,
`BLInitToken`). Function map:

| Function | Role |
|---|---|
| `sub_25EC0` | `IsUnlocked()` — returns `(u8)*(0x1EB8AD)` |
| `sub_26950` | `SetUnlocked(v)` — no-op if unchanged; bumps `UnlockCount` @`0x1EC540` when v!=0 (reset at `>=9992`); writes `+0xD`; persists via `sub_18E70(1)` |
| `sub_26BB0` | devinfo initializer — checks `"SAMANDR-BOOT!"` @`unk_1EB8A0`, resets `+0xD/+0xE/+0xF=0`, sets `+0x90=1`, zeroes count |
| `sub_CC260` | OEM policy — logs `[OEM]LOCK:%d` from `*(x+240)` and returns 0 (**neutered**, same as S24U `0xa13b0`) |
| `sub_26240(kind, v)` | apply dispatcher — SetUnlocked/SetUnlockCritical + recovery `--wipe_data` + userdata erase on success |
| `sub_26020(target, step)` | sync — compares IsUnlocked vs target, applies via `sub_26240`, reboots to recovery on change |
| `sub_DA090` | `BLInitToken` — requires `"ENG"` magic in token buffer else `[EM] Token not exist`; then `sub_DDEE0` |
| `sub_D9000/D9140` | `BLReadToken/BLWriteToken` — steady @20480, len 69632 (0x11000) |
| `sub_DD590` | `BLEmProcess(cmd)` — builds request (DID, ESI, model string `"SM-F946B"`, token blob) -> TA via `sub_DD380`; response flags drive updates |
| `sub_D9D30(m)` | `GetEMBit(m)` = `(bitmap[m>>6] >> m) & 1`, bitmap @`dword_208760` |

The EM-sync chain lives in early init `sub_8A98`:

```asm
BL   sub_DA090        ; BLInitToken
MOV  W0, #3           ; MODE_CUST_KERNEL
BL   sub_D9D30        ; GetEMBit(3)
TST  W0, #0xFF
CSET W0, NE           ; target_state = bit3
MOV  W1, WZR          ; step = 0
BL   sub_26020        ; SetUnlocked(1) + FRP wipe + reboot-to-recovery if changed
```

### Who fills the mode bitmap

Only the **trustlet response**: `BLEmProcess` copies 32 bytes from the TA
reply into `dword_208760` when response flags include bit 0x20
(`"[EM]%a : Need Update Bits"`). There is **no local parser** — the other
bitmap accessors are pure getters (`sub_D9D80` copy-out, `sub_D9E30/D9E80`
word reads, `sub_D9DD0` bit0 check with a hardware override
`sub_D9A50`). ABL never authenticates or even parses the steady token for
modes itself; it forwards it to the TA every boot and trusts what comes
back. Token install (TA cmd 2) is RPMB-backed and needs a Samsung-signed
blob. Conclusion matches oems24-audit exactly: **no on-device injection
point for mode 3.**

## Live device state (RFCWC0G1JZ… / SM-F946B, GZE5)

| Item | Value |
|---|---|
| `ro.boot.kg` | **0x1 — Knox already fused** (device was legitimately unlocked on One UI 7; One UI 8.5 auto-locked it) |
| `ro.boot.warranty_bit` | 1 |
| `androidboot.ulcnt` | 1 (that historical unlock) |
| `ro.oem_unlock_supported` | 1 (still advertised) |
| verifiedbootstate / flash.locked / other.locked | green / 1 / 1 |
| devinfo | magic OK, `+0xD=0`, `+0xE=0`, `+0x90=1`, UnlockCount `+0xCA0 = 0` |
| steady token area (@20480..0x11480) | **empty — no `"ENG"` token installed anywhere in image** |
| `em` partition | all zeros |

Note our devinfo `UnlockCount` is at `+0xCA0` (global `0x1EC540`), not the
S24U-reported `+0xc88` — struct differs slightly between builds; the
`+0xD/+0xE/+0x90` layout is identical.

## Verdict

1. The unlock *machinery* survives intact on Fold5 GZE5, but every
   authorization path terminates in the engmode trustlet, and the device
   holds no token; the issuance side does not exist on-device.
2. Manually writing `devinfo+0xD` would be reverted by the `sub_8A98`
   sync block on normal boots **with a forced userdata wipe**
   (`sub_26020` -> recovery `--wipe_data`) — destructive even if it
   worked, and it is a partition write, which this firmware turns into a
   potential hard brick. Not attempted, not recommended.
3. Therefore: bootloader-level persistence is blocked without a valid
   Samsung-signed Engineering Mode token containing mode 3. Persistence
   work continues on the software side (auto-root keeper) instead.

## Follow-up: remaining surfaces exhausted (same session)

| Surface | Finding |
|---|---|
| `sub_D9A50` fuse/flag state machine | States {0,1,3}, setters via `sub_C70D0(25/26/27)` ("set D/U", "force-U"), terminal `[EM]F: U`. Its result **overrides the TA bitmap only for bit 0** (`sub_D9DD0`) — and that getter's single consumer is `sub_595B0` at `0x5b8a8`, which formats it into the informational cmdline property `androidboot.em.status=0x%x`. No gate rides on it. Live value on device: `ro.boot.em.status=0x0`. |
| ABL manual-unlock flow | `sub_71A50` calls `BLInitToken`, then the neutered OEM policy `sub_CC260` twice — the bootloader's own interactive path asks a function that unconditionally returns false. |
| AVB persistent values | `ReadPersistentValue/WritePersistentValue` ops + `avb.persistent_digest.*` strings exist (rollback digest storage), unrelated to lock state. |
| Android-side OemLock | `oem_lock` (`android.service.oemlock.IOemLockService`) binder service present, engmode HAL + `emservice` running (S24U topology confirmed live). Even a fully prepared Android-side allowance dies at the ABL policy stub above. |

Every candidate route now terminates at one of: TA-signed token (no issuance
authority), Samsung image signatures (Odin Auth / fused verification), or the
policy stub. Manual `devinfo` writes additionally trigger the destructive sync
(lock + userdata wipe + reboot-to-recovery) on the dominant boot path.

## Safety record

Commands used against the device were limited to: `ls`, `dd if=<block>
of=/data/local/tmp`, `getprop`, `cat /proc/*`. Dump files were pulled and
the temp copies removed. Zero writes to any block device, zero Binder
transactions toward engmode services, no token/RPMB/fuse operations.
