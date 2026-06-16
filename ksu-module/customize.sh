#!/system/bin/sh
# KernelSU module - OPPO Watch Unlock Fix
# Installation script

MODDIR=${0%/*}

# Set permissions
chmod 755 $MODDIR/service.sh
chmod 755 $MODDIR/post-fs-data.sh

ui_print "========================================="
ui_print " OPPO Watch Unlock Fix (KernelSU)"
ui_print "========================================="
ui_print ""
ui_print "This module will:"
ui_print "1. Patch system properties to fake clean boot state"
ui_print "2. Monitor and maintain property values"
ui_print "3. Help bypass root detection in sysintegrity"
ui_print ""
ui_print "Note: This alone may not be enough to unlock"
ui_print "the watch. It's part of a multi-layer approach."
ui_print ""
ui_print "Installation complete!"
ui_print "Please reboot your device."
