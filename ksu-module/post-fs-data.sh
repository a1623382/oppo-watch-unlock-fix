#!/system/bin/sh
# KernelSU module - OPPO Watch Unlock Fix
# Runs in post-fs-data phase (before zygote)

MODDIR=${0%/*}

# Wait for post-fs-data
while [ "$(getprop sys.boot_completed)" != "1" ]; do
  sleep 0.5
done

LOGFILE="/data/local/tmp/oppo_watch_fix_postfs.log"
echo "$(date) [KSU] post-fs-data started" > $LOGFILE

# Patch properties as early as possible
resetprop "ro.boot.verifiedbootstate" "green" 2>/dev/null
resetprop "ro.boot.flash.locked" "1" 2>/dev/null
resetprop "ro.debuggable" "0" 2>/dev/null
resetprop "ro.secure" "1" 2>/dev/null
resetprop "ro.build.type" "user" 2>/dev/null
resetprop "ro.build.tags" "release-keys" 2>/dev/null
resetprop "ro.boot.selinux" "1" 2>/dev/null

echo "$(date) [KSU] post-fs-data properties patched" >> $LOGFILE
