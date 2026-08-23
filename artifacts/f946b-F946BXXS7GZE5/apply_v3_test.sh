#!/system/bin/sh
# Exact replica of KSU_APPLY_SCRIPT v3 (src/common.h) for on-device validation.
if [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ]; then
  echo 'apply-modules: boot not completed; deferring' >&2; exit 42; fi;
ksud='';
for p in /data/local/tmp/ksud-s25u-kdp /data/adb/ksud /data/adb/ksu/bin/ksud; do
  [ -x "$p" ] && ksud="$p" && break;
done;
if [ -z "$ksud" ]; then
  echo 'apply-modules: no ksud binary found' >&2; exit 1; fi;
echo "apply-modules: using ksud=$ksud";
if [ "$ksud" != "/data/adb/ksud" ]; then
  cp "$ksud" /data/adb/ksud 2>/dev/null && chmod 755 /data/adb/ksud && echo 'apply-modules: repaired /data/adb/ksud'; fi;
rc=0;
for s in post-fs-data services boot-completed; do
  "$ksud" "$s" >/dev/null 2>&1 || rc=1;
  echo "apply-modules: ksud $s exit=$? ($ksud)";
done;
if [ "$rc" != "0" ]; then
  echo 'apply-modules: ksud stages failed; leaving zygote alone' >&2; exit $rc; fi;
if [ -d /data/adb/modules/zygisk_vector ] && [ -z "$(pidof vectord)" ]; then
  echo 'apply-modules: vectord missing; re-running services';
  "$ksud" services >/dev/null 2>&1; sleep 2; fi;
echo "apply-modules: vectord pid=$(pidof vectord)";
killed=0;
for p in $(pidof zygote64) $(pidof zygote); do
  kill -9 $p 2>/dev/null && killed=1;
done;
if [ "$killed" = 0 ]; then echo 'apply-modules: no zygote killed' >&2; exit 1; fi;
echo 'apply-modules: zygote restarted for module pickup'; exit 0
