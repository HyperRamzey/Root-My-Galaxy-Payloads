#!/system/bin/sh
# wcg_watchdog.sh — keep persist.sys.sf.native_mode=0 for a bounded window.
#
# Samsung's ColorDisplayService.setUp() rewrites persist.sys.sf.native_mode to 1
# (UNMANAGED) during system_server startup, which forces Configuration to
# nowidecg. This watchdog re-asserts 0 (MANAGED) faster than the framework can
# read the stale value, so WindowManagerService computes widecg.
#
# Launched by post-fs-data.sh and service.sh (they pkill any prior instance
# first, so there is never more than one). Self-exits after DURATION seconds.
#
# usage: wcg_watchdog.sh [duration_seconds] [poll_seconds]

PROP=persist.sys.sf.native_mode
RP=/data/adb/ksu/bin/resetprop
[ -x "$RP" ] || RP=resetprop

DURATION="${1:-300}"
POLL="${2:-0.2}"

end=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
    if [ "$(getprop "$PROP")" != "0" ]; then
        "$RP" "$PROP" 0 2>/dev/null || setprop "$PROP" 0
    fi
    sleep "$POLL"
done
