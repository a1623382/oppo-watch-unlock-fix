#!/system/bin/sh
# KernelSU module - OPPO Watch Unlock Fix
# Runs at boot to modify system properties

MODDIR=${0%/*}

# Wait for boot to complete
while [ "$(getprop sys.boot_completed)" != "1" ]; do
  sleep 1
done

sleep 5

LOGFILE="/data/local/tmp/oppo_watch_fix.log"
echo "$(date) [KSU] Module started" > $LOGFILE

# Only patch specific properties needed for integrity check
# Do NOT touch build properties or system-critical properties
resetprop "ro.boot.verifiedbootstate" "green" 2>/dev/null
echo "$(date) [PROP] patched verifiedbootstate" >> $LOGFILE

resetprop "ro.boot.flash.locked" "1" 2>/dev/null
echo "$(date) [PROP] patched flash.locked" >> $LOGFILE

resetprop "ro.boot.selinux" "1" 2>/dev/null
echo "$(date) [PROP] patched selinux" >> $LOGFILE

echo "$(date) [KSU] Done" >> $LOGFILE
