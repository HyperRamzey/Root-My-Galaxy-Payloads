#!/system/bin/sh
# post-fs-data.sh — runs early (after /data is mounted), before system_server.
# Set the WCG gate property and start the watchdog that defends it against
# Samsung's ColorDisplayService.setUp() reset.

MODDIR="${0%/*}"
PROP=persist.sys.sf.native_mode
LOG=/data/local/tmp/wcg_f946b.log
RP=/data/adb/ksu/bin/resetprop
[ -x "$RP" ] || RP=resetprop

log() { echo "[post-fs-data] $(date '+%Y-%m-%d %H:%M:%S') $*" >>"$LOG"; }

# Set the gate property to MANAGED (0) so WCG is allowed.
"$RP" "$PROP" 0 2>/dev/null || setprop "$PROP" 0
log "set $PROP=0 (was persisted as 1 by Samsung); now $(getprop "$PROP")"

# Start the watchdog (kills any prior instance first). It re-asserts 0 for the
# next 300s, covering the whole system_server startup race. Launched via `sh`
# so it works even if the exec bit was not preserved by the installer.
pkill -f wcg_watchdog.sh 2>/dev/null
if [ -f "$MODDIR/wcg_watchdog.sh" ]; then
    nohup sh "$MODDIR/wcg_watchdog.sh" 300 0.2 >/dev/null 2>&1 &
    log "watchdog started (300s / 0.2s poll)"
else
    log "watchdog script missing: $MODDIR/wcg_watchdog.sh"
fi
