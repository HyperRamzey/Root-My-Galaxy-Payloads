#!/system/bin/sh
# service.sh — runs on late_start service, after post-fs-data and before/around
# system_server bringing up services. Re-asserts the WCG gate property, makes
# sure the watchdog is running, and schedules a post-boot safety net that forces
# a display recompute if the Configuration is still nowidecg.

MODDIR="${0%/*}"
PROP=persist.sys.sf.native_mode
LOG=/data/local/tmp/wcg_f946b.log
RP=/data/adb/ksu/bin/resetprop
[ -x "$RP" ] || RP=resetprop

log() { echo "[service] $(date '+%Y-%m-%d %H:%M:%S') $*" >>"$LOG"; }

set_prop() { "$RP" "$PROP" 0 2>/dev/null || setprop "$PROP" 0; }

log "module dir: $MODDIR"

# 1) Re-assert the gate property immediately.
set_prop
log "re-asserted $PROP=0; now $(getprop "$PROP")"

# 2) Make sure the watchdog is running (restart if the post-fs-data one died).
if ! pgrep -f wcg_watchdog.sh >/dev/null 2>&1; then
    pkill -f wcg_watchdog.sh 2>/dev/null
    if [ -x "$MODDIR/wcg_watchdog.sh" ]; then
        nohup "$MODDIR/wcg_watchdog.sh" 300 0.2 >/dev/null 2>&1 &
        log "watchdog (re)started (300s / 0.2s poll)"
    fi
else
    log "watchdog already running"
fi

# 3) Post-boot safety net: if the Configuration is still nowidecg once the
#    device has finished booting, force a display recompute with a minimal,
#    override-preserving density blip. Runs in the background; does nothing if
#    widecg is already active.
(
    # Wait for boot_completed (up to 180s).
    i=0
    while [ "$i" -lt 180 ]; do
        [ "$(getprop sys.boot_completed)" = "1" ] && break
        sleep 1
        i=$((i + 1))
    done
    sleep 25

    cfg=$(cmd activity get-config 2>/dev/null | grep -oE 'widecg|nowidecg' | head -1)
    if [ "$cfg" != "nowidecg" ]; then
        log "post-boot config=${cfg:-unknown}; no recompute needed"
        exit 0
    fi

    log "post-boot config=nowidecg; forcing recompute via density blip"
    phys=$(wm density 2>/dev/null | grep -oE 'Physical density: [0-9]+' | grep -oE '[0-9]+' | head -1)
    over=$(wm density 2>/dev/null | grep -oE 'Override density: [0-9]+' | grep -oE '[0-9]+' | head -1)
    cur="${over:-$phys}"
    if [ -n "$cur" ]; then
        wm density $((cur - 1)) >/dev/null 2>&1
        sleep 2
        if [ -n "$over" ]; then
            wm density "$over" >/dev/null 2>&1
        else
            wm density reset >/dev/null 2>&1
        fi
        sleep 2
        set_prop
        cfg2=$(cmd activity get-config 2>/dev/null | grep -oE 'widecg|nowidecg' | head -1)
        log "density blip done (cur=$cur); config now ${cfg2:-unknown}"
    else
        log "could not determine density; skipping blip"
    fi
) >/dev/null 2>&1 &

log "done"
