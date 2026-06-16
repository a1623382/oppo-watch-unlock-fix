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
        XposedBridge.log(TAG + ": === LINKER v1.6.0 ===");
        hookCipherObserve(lpparam);
        hookSendSecureData(lpparam);
    }

    private void hookSendSecureData(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String cn = "com.oplus.linker.unlock.connect.ConnectionManager";
            Class<?> cl = Class.forName(cn, false, lpparam.classLoader);
            XposedBridge.log(TAG + ": [REG] Found ConnectionManager");

            for (Method m : cl.getDeclaredMethods()) {
                String name = m.getName();
                if (!name.contains("sendSecure") && !name.contains("secureSend")) continue;

                Class<?>[] params = m.getParameterTypes();
                boolean hasByteArray = false;
                int byteIdx = -1;
                int strIdx = -1;
                for (int i = 0; i < params.length; i++) {
                    if (params[i] == byte[].class && byteIdx == -1) byteIdx = i;
                    if (params[i] == String.class && strIdx == -1) strIdx = i;
                    if (params[i] == byte[].class) hasByteArray = true;
                }
                if (!hasByteArray) continue;

                final String sig = cn + "." + name;
                final int fByteIdx = byteIdx;
                final int fStrIdx = strIdx;

                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        String op = fStrIdx >= 0 && p.args[fStrIdx] != null ?
                            (String) p.args[fStrIdx] : "unknown";

                        if (fByteIdx >= 0 && p.args[fByteIdx] instanceof byte[]) {
                            byte[] data = (byte[]) p.args[fByteIdx];
                            XposedBridge.log(TAG + ": [REG] " + op + " len=" + data.length);

                            if (op.contains("register") || op.contains("key") || op.contains("agreement")) {
                                XposedBridge.log(TAG + ": [REG-KEY] " + op + " hex=" + bytesToHex(data));

                                try {
                                    String str = new String(data, "UTF-8");
                                    int idx = str.indexOf("sysIntegrity");
                                    if (idx >= 0) {
                                        XposedBridge.log(TAG + ": [REG-KEY] sysIntegrity at offset=" + idx);
                                        XposedBridge.log(TAG + ": [REG-KEY] context: " +
                                            str.substring(Math.max(0, idx - 20),
                                            Math.min(str.length(), idx + 40)));
                                    }
                                } catch (Throwable ignored) {}
                            }
                        }
                    }
                });
                XposedBridge.log(TAG + ": [REG] Hooked " + sig);
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": [REG] ConnectionManager not found: " + t);
        }
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
                            int idx = str.indexOf("\"sysIntegrity\":false");
                            if (idx >= 0) {
                                XposedBridge.log(TAG + ": [CIPHER] Found sysIntegrity:false at offset=" + idx);

                                byte[] replacement = "\"sysIntegrity\":true".getBytes("UTF-8");
                                byte[] original = "\"sysIntegrity\":false".getBytes("UTF-8");

                                System.arraycopy(replacement, 0, input, idx, replacement.length);

                                byte[] remaining = new byte[input.length - idx - original.length];
                                System.arraycopy(input, idx + original.length, remaining, 0, remaining.length);
                                System.arraycopy(remaining, 0, input, idx + replacement.length, remaining.length);

                                XposedBridge.log(TAG + ": [CIPHER-PATCH] sysIntegrity:false -> true (len " +
                                    input.length + " -> " + (input.length - 1) + ")");
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
            XposedBridge.log(TAG + ": Hooked Cipher (patch mode)");
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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(bytes.length, 64);
        for (int i = 0; i < limit; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xFF));
            if ((i + 1) % 16 == 0) sb.append("\n  ");
            else sb.append(" ");
        }
        if (bytes.length > 64) sb.append("...(").append(bytes.length).append(" total)");
        return sb.toString();
    }
}
