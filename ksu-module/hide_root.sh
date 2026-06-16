#!/system/bin/sh
# KernelSU module - OPPO Watch Unlock Fix
# Hides root indicators from sysintegrity process

LOGFILE="/data/local/tmp/oppo_watch_fix.log"

echo "$(date) [HIDE] Starting root hiding" >> $LOGFILE

# Hide su binary paths
for su_path in /system/bin/su /system/xbin/su /sbin/su /data/adb/su /cache/su; do
  if [ -f "$su_path" ]; then
    mount --bind /system/bin/sh "$su_path" 2>/dev/null
    echo "$(date) [HIDE] Mounted over $su_path" >> $LOGFILE
  fi
done

# Hide KernelSU files
for ksu_path in /data/adb/ksu /data/adb/modules /data/adb/ksud; do
  if [ -d "$ksu_path" ]; then
    mount --bind /dev/null "$ksu_path" 2>/dev/null
    echo "$(date) [HIDE] Mounted over $ksu_path" >> $LOGFILE
  fi
done

# Hide Magisk files (if present)
for magisk_path in /data/adb/magisk /data/adb/magisk.db; do
  if [ -e "$magisk_path" ]; then
    mount --bind /dev/null "$magisk_path" 2>/dev/null
    echo "$(date) [HIDE] Mounted over $magisk_path" >> $LOGFILE
  fi
done

# Hide /proc/1/maps entries for root tools
# This is tricky and may not work on all devices

echo "$(date) [HIDE] Root hiding complete" >> $LOGFILE
