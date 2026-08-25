#!/system/bin/sh
# Revive the Vector daemon after an apply-time zygote bounce.
MODDIR=/data/adb/modules/zygisk_vector
cd "$MODDIR" || exit 1
export CLASSPATH="$MODDIR/daemon.apk"
nohup /system/bin/app_process64 /system/bin --nice-name=vectord \
  -Djava.class.path="$MODDIR/daemon.apk" \
  org.matrix.vector.daemon.VectorDaemon --system-server-max-retry=3 \
  >/data/local/tmp/vectord-revive.log 2>&1 &
echo "spawned $!"
sleep 3
ps -A -o PID,NAME | grep -i vectord
echo "--- log ---"
head -5 /data/local/tmp/vectord-revive.log
