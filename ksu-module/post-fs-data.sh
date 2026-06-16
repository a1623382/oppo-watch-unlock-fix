#!/system/bin/sh
# KernelSU module - OPPO Watch Unlock Fix
# Minimal post-fs-data script - only patch critical properties

MODDIR=${0%/*}

# Only patch the most critical properties
resetprop "ro.boot.verifiedbootstate" "green" 2>/dev/null
resetprop "ro.boot.flash.locked" "1" 2>/dev/null
resetprop "ro.boot.selinux" "1" 2>/dev/null
