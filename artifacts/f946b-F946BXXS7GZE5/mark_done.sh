#!/system/bin/sh
BID=$(cat /proc/sys/kernel/random/boot_id)
UP=$(cut -d' ' -f1 /proc/uptime | cut -d. -f1)
echo "$BID $UP" > /data/local/tmp/.cve43499-modules-done
cat /data/local/tmp/.cve43499-modules-done
