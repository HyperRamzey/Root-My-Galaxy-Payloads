#!/system/bin/sh
# Wide Color Gamut enabler — SM-F946B
# Stop the watchdog and restore Samsung's stock value on uninstall so the
# display returns to the vendor-tuned native color mode.

# Stop any running watchdog so it does not keep re-asserting 0.
pkill -f wcg_watchdog.sh 2>/dev/null

PROP=persist.sys.sf.native_mode
if [ -x /data/adb/ksu/bin/resetprop ]; then
    /data/adb/ksu/bin/resetprop "$PROP" 1
elif command -v resetprop >/dev/null 2>&1; then
    resetprop "$PROP" 1
else
    setprop "$PROP" 1
fi
rm -f /data/local/tmp/wcg_f946b.log
exit 0
