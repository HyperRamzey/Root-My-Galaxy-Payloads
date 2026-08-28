#!/system/bin/sh
# Wide Color Gamut enabler — install-time guard.
# This module is device-specific: it flips a global display property and relies on
# the exact Samsung WMS gate present on SM-F946B (OneUI 8 / Android 16). Refuse
# to install on other models so it cannot silently alter another device's color
# pipeline.

MODEL=$(getprop ro.product.model)
DEVICE=$(getprop ro.product.device)

ui_print "- Device: $MODEL ($DEVICE)"

case "$MODEL" in
SM-F946B* | SM-F946*)
    ui_print "- Supported Fold5 model detected."
    ;;
*)
    ui_print "! Unsupported model: $MODEL"
    ui_print "! This module targets SM-F946B (Galaxy Z Fold5)."
    ui_print "! Aborting to avoid altering another device's color pipeline."
    abort
    ;;
esac

# Ensure the scripts are executable.
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

exit 0
