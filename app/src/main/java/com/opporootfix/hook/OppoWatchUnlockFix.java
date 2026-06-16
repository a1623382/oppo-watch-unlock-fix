package com.opporootfix.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Method;

public class OppoWatchUnlockFix implements IXposedHookLoadPackage {

    private static final String TAG = "OPPOWatchFix";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        String pkg = lpparam.packageName;
        XposedBridge.log(TAG + ": Loaded pkg=" + pkg + " proc=" + lpparam.processName);

        if ("com.oplus.linker".equals(pkg)) {
            hookLinker(lpparam);
        } else if (pkg.startsWith("com.heytap.htms")) {
            hookHtms(lpparam);
        } else if ("com.heytap.health".equals(pkg)) {
            hookHealth(lpparam);
        }
    }

    private void hookLinker(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === LINKER v1.5.0 ===");
        hookCipherObserve(lpparam);
    }

    private void hookCipherObserve(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedBridge.hookMethod(
                javax.crypto.Cipher.class.getMethod("doFinal", byte[].class),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        byte[] input = (byte[]) p.args[0];
                        if (input == null || input.length < 50) return;

                        try {
                            String str = new String(input, "UTF-8");
                            int idx = str.indexOf("sysIntegrity");
                            if (idx >= 0) {
                                XposedBridge.log(TAG + ": [CIPHER] sysIntegrity found at offset=" + idx +
                                    " total=" + input.length);

                                StringBuilder around = new StringBuilder();
                                int start = Math.max(0, idx - 16);
                                int end = Math.min(input.length, idx + 48);
                                for (int i = start; i < end; i++) {
                                    int b = input[i] & 0xFF;
                                    around.append(String.format("%02x ", b));
                                    if ((i - start + 1) % 16 == 0) around.append("\n  ");
                                }
                                XposedBridge.log(TAG + ": [CIPHER-CTX] around sysIntegrity:\n  " + around);

                                XposedBridge.log(TAG + ": [CIPHER-ASCII] " + str.substring(
                                    Math.max(0, idx - 32), Math.min(str.length(), idx + 64)));
                            }
                        } catch (Throwable ignored) {}
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Throwable t = p.getThrowable();
                        if (t != null && (t.toString().contains("BadPadding") ||
                            t.toString().contains("BAD_DECRYPT"))) {
                            p.setThrowable(null);
                            p.setResult(new byte[0]);
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked Cipher (observe only)");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Cipher hook failed: " + t);
        }
    }

    private void hookHtms(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === HTMS proc=" + lpparam.processName + " ===");
        hookSystemProperties();
        hookBuildClass();
    }

    private void hookSystemProperties() {
        try {
            Class<?> spClass = Class.forName("android.os.SystemProperties");
            Method get1 = spClass.getMethod("get", String.class);
            Method get2 = spClass.getMethod("get", String.class, String.class);

            XposedBridge.hookMethod(get1, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    String key = (String) p.args[0];
                    if (key == null) return;
                    String val = (String) p.getResult();

                    if (key.contains("verifiedbootstate")) {
                        if (!"green".equals(val)) {
                            XposedBridge.log(TAG + ": [PROP] " + key + "=" + val + " -> green");
                            p.setResult("green");
                        }
                    } else if (key.contains("flash.locked")) {
                        if (!"1".equals(val)) { p.setResult("1"); }
                    } else if (key.equals("ro.debuggable")) { p.setResult("0"); }
                    else if (key.equals("ro.secure")) { p.setResult("1"); }
                    else if (key.equals("ro.build.type")) {
                        if ("userdebug".equals(val) || "eng".equals(val)) { p.setResult("user"); }
                    } else if (key.contains("selinux")) { p.setResult("1"); }
                    else if (key.contains("ro.adb.secure")) { p.setResult("1"); }
                }
            });

            XposedBridge.hookMethod(get2, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    String key = (String) p.args[0];
                    if (key == null) return;
                    if (key.contains("verifiedbootstate")) { p.setResult("green"); }
                    else if (key.contains("flash.locked")) { p.setResult("1"); }
                    else if (key.equals("ro.debuggable")) { p.setResult("0"); }
                    else if (key.equals("ro.secure")) { p.setResult("1"); }
                    else if (key.equals("ro.build.type")) {
                        String v = (String) p.getResult();
                        if ("userdebug".equals(v) || "eng".equals(v)) { p.setResult("user"); }
                    } else if (key.contains("selinux")) { p.setResult("1"); }
                }
            });
            XposedBridge.log(TAG + ": Hooked SystemProperties");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": SystemProperties hook failed: " + t);
        }
    }

    private void hookBuildClass() {
        try {
            XposedHelpers.setStaticObjectField(android.os.Build.class, "TYPE", "user");
            XposedHelpers.setStaticObjectField(android.os.Build.class, "TAGS", "release-keys");
            XposedBridge.log(TAG + ": Patched Build fields");
        } catch (Throwable t) {}
    }

    private void hookHealth(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === HEALTH ===");
    }
}
