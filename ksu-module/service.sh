#!/system/bin/sh
# KernelSU module - OPPO Watch Unlock Fix
# Runs at boot to modify system properties and hook stdsrp

MODDIR=${0%/*}

# Wait for boot to complete
while [ "$(getprop sys.boot_completed)" != "1" ]; do
  sleep 1
done

# Wait a bit more for services to start
sleep 5

LOGFILE="/data/local/tmp/oppo_watch_fix.log"
echo "$(date) [KSU] Module started" > $LOGFILE

# Function to safely set property
set_prop() {
  local key="$1"
  local val="$2"
  local current=$(getprop "$key")
  if [ "$current" != "$val" ]; then
    resetprop "$key" "$val" 2>/dev/null || setprop "$key" "$val" 2>/dev/null
    echo "$(date) [PROP] $key: $current -> $val" >> $LOGFILE
  fi
}

# Fake clean boot state
set_prop "ro.boot.verifiedbootstate" "green"
set_prop "ro.boot.flash.locked" "1"
set_prop "ro.boot.veritymode" "1"
set_prop "ro.debuggable" "0"
set_prop "ro.secure" "1"
set_prop "ro.adb.secure" "1"
set_prop "ro.build.type" "user"
set_prop "ro.build.tags" "release-keys"
set_prop "ro.boot.selinux" "1"
set_prop "ro.build.display.id" "PJZ110_16.0.1.201CN01C00"
set_prop "ro.build.version.incremental" "PJZ110_16.0.1.201CN01C00"
set_prop "ro.build.version.opporom" "16.0.1"
set_prop "ro.build.version.coloros" "16.0.1"
set_prop "ro.product.model" "PJZ110"
set_prop "ro.product.brand" "OPPO"
set_prop "ro.product.device" "OP5D0DL1"
set_prop "ro.product.name" "OP5D0DL1"
set_prop "persist.sys.dalvik.vm.lib.2" "libart.so"
set_prop "ro.dalvik.vm.native.bridge" "0"
set_prop "ro.hardware.chipname" "sm8650"
set_prop "ro.board.platform" "kalama"

echo "$(date) [KSU] Properties patched" >> $LOGFILE

# Hide root indicators
sh $MODDIR/hide_root.sh

# Monitor sysintegrity process and kill it if needed to force restart
while true; do
  # Check if sysintegrity process is running
  SYSPID=$(pidof com.heytap.htms:sysintegrity 2>/dev/null)
  if [ -n "$SYSPID" ]; then
    # Check if our properties are still set
    CURRENT_STATE=$(getprop ro.boot.verifiedbootstate)
    if [ "$CURRENT_STATE" != "green" ]; then
      echo "$(date) [MONITOR] Properties reset, repatching..." >> $LOGFILE
      set_prop "ro.boot.verifiedbootstate" "green"
      set_prop "ro.boot.flash.locked" "1"
      set_prop "ro.debuggable" "0"
      set_prop "ro.secure" "1"
      set_prop "ro.build.type" "user"
      set_prop "ro.build.tags" "release-keys"
      set_prop "ro.boot.selinux" "1"
    fi
  fi
  sleep 10
done
