package com.opporootfix.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

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
        XposedBridge.log(TAG + ": === LINKER v1.3.2 ===");

        hookCipher();
        hookJSONObjectSysIntegrity();
        hookStringBuilderErrorPatch();
        hookKnownLinkerClasses(lpparam);
    }

    // ==================== LINKER ====================

    private void hookCipher() {
        try {
            XposedBridge.hookMethod(
                javax.crypto.Cipher.class.getMethod("doFinal", byte[].class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Throwable t = p.getThrowable();
                        if (t != null && (t.toString().contains("BadPadding") ||
                            t.toString().contains("BAD_DECRYPT"))) {
                            p.setThrowable(null);
                            p.setResult(new byte[0]);
                            XposedBridge.log(TAG + ": Cipher error intercepted");
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked Cipher");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Cipher hook failed: " + t);
        }
    }

    private void hookJSONObjectSysIntegrity() {
        try {
            XposedBridge.hookMethod(
                org.json.JSONObject.class.getMethod("toString"),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String s = (String) p.getResult();
                        if (s != null && s.contains("\"sysIntegrity\":false")) {
                            p.setResult(s.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true"));
                            XposedBridge.log(TAG + ": patched sysIntegrity -> true");
                        }
                    }
                });
            XposedBridge.hookMethod(
                org.json.JSONObject.class.getMethod("toString", int.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String s = (String) p.getResult();
                        if (s != null && s.contains("\"sysIntegrity\":false")) {
                            p.setResult(s.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true"));
                        }
                    }
                });
            XposedBridge.hookMethod(
                org.json.JSONObject.class.getMethod("getBoolean", String.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        if ("sysIntegrity".equals(p.args[0]) && Boolean.FALSE.equals(p.getResult())) {
                            p.setResult(true);
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked JSONObject");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": JSONObject hook failed: " + t);
        }
    }

    private void hookStringBuilderErrorPatch() {
        try {
            XposedBridge.hookMethod(
                StringBuilder.class.getMethod("toString"),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String s = (String) p.getResult();
                        if (s == null) return;

                        if (s.contains("sysIntegrity") && s.contains("false")) {
                            String patched = s.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true");
                            p.setResult(patched);
                            XposedBridge.log(TAG + ": [SB] patched sysIntegrity");
                        }

                        if (s.contains("errorCode") && s.contains("13")) {
                            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                            StringBuilder trace = new StringBuilder();
                            for (int i = 3; i < Math.min(stack.length, 6); i++) {
                                trace.append(stack[i].toString()).append("\n");
                            }
                            XposedBridge.log(TAG + ": [SB] errorCode=13 stack:\n" + trace);
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked StringBuilder");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": StringBuilder hook failed: " + t);
        }
    }

    private void hookKnownLinkerClasses(XC_LoadPackage.LoadPackageParam lpparam) {
        int count = 0;
        String[] prefixes = {
            "com.oplus.linker.unlock",
            "com.oplus.linker.crypto",
            "com.oplus.linker.integrity",
            "com.oplus.linker.socket",
            "com.oplus.linker.srp",
            "com.oplus.linker"
        };
        String[] suffixes = {
            "ConnectionSocket", "ConnectionManager", "UnlockManager",
            "EncryptionUtils", "ProtoDataGenerator", "WatchUnlockManager",
            "UnlockHelper", "IntegrityChecker", "SrpUtils",
            "AttestationUtils", "PhoneUnlockWatchManager",
            "SmartLockManager", "TokenManager", "LockManager",
            "UnlockDataCache", "PhoneConnectionProvider"
        };

        for (String prefix : prefixes) {
            for (String suffix : suffixes) {
                String cn = prefix + "." + suffix;
                try {
                    Class<?> cl = Class.forName(cn, false, lpparam.classLoader);
                    hookSpecificMethods(cl, cn);
                    count++;
                } catch (Throwable ignored) {}
            }
        }
        XposedBridge.log(TAG + ": Known classes hooked: " + count);
    }

    private void hookSpecificMethods(Class<?> clazz, String className) {
        for (Method m : clazz.getDeclaredMethods()) {
            try {
                String name = m.getName();
                Class<?>[] params = m.getParameterTypes();

                boolean targetMethod = name.contains("processLock") ||
                    name.contains("LockEvent") || name.contains("lockEvent") ||
                    name.contains("sendSecure") || name.contains("encrypt") ||
                    name.contains("decrypt") || name.contains("processToken") ||
                    name.contains("register") || name.contains("getLock") ||
                    name.contains("protoData") || name.contains("ProtoData");

                boolean hasByteArray = false;
                boolean hasString = false;
                for (Class<?> pt : params) {
                    if (pt == byte[].class) hasByteArray = true;
                    if (pt == String.class) hasString = true;
                }

                if (!targetMethod && !hasByteArray) continue;

                final String sig = className + "." + name;
                final boolean fb = hasByteArray;
                final boolean fs = hasString;

                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        if (fb) {
                            for (Object arg : p.args) {
                                if (arg instanceof byte[]) {
                                    byte[] data = (byte[]) arg;
                                    if (data.length > 5) {
                                        XposedBridge.log(TAG + ": [BYTE>>] " + sig + " len=" + data.length);
                                        logRelevantBytes(data, sig);
                                    }
                                }
                            }
                        }
                        if (fs) {
                            for (Object arg : p.args) {
                                if (arg instanceof String) {
                                    String s = (String) arg;
                                    if (s.contains("errorCode") || s.contains("sysIntegrity") ||
                                        s.contains("unlock") || s.contains("token")) {
                                        XposedBridge.log(TAG + ": [STR>>] " + sig + " str=" +
                                            s.substring(0, Math.min(200, s.length())));
                                    }
                                }
                            }
                        }
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Throwable t = p.getThrowable();
                        if (t != null) {
                            XposedBridge.log(TAG + ": [ERR] " + sig + " threw: " + t);
                            p.setThrowable(null);
                        }

                        Object result = p.getResult();
                        if (result instanceof Boolean && !(Boolean) result) {
                            p.setResult(true);
                            XposedBridge.log(TAG + ": [BOOL] " + sig + " false->true");
                        } else if (result instanceof Integer && (Integer) result != 0) {
                            p.setResult(0);
                            XposedBridge.log(TAG + ": [INT] " + sig + " " + result + "->0");
                        } else if (result instanceof byte[]) {
                            byte[] data = (byte[]) result;
                            if (data.length > 5) {
                                XposedBridge.log(TAG + ": [BYTE<<] " + sig + " ret len=" + data.length);
                                logRelevantBytes(data, sig);
                            }
                        }
                    }
                });
            } catch (Throwable ignored) {}
        }
    }

    private void logRelevantBytes(byte[] data, String context) {
        try {
            String str = new String(data, "UTF-8");
            String lower = str.toLowerCase();
            if (lower.contains("integrity") || lower.contains("sysint") ||
                lower.contains("attest") || lower.contains("boot") ||
                lower.contains("security")) {
                XposedBridge.log(TAG + ": [BYTE-KEY] " + context);
            }
        } catch (Throwable ignored) {}
    }

    // ==================== HTMS ====================

    private void hookHtms(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === HTMS proc=" + lpparam.processName + " ===");
        hookSystemProperties();
        hookBuildClass();
        hookKnownSrpClasses(lpparam);
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
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Build patch failed: " + t);
        }
    }

    private void hookKnownSrpClasses(XC_LoadPackage.LoadPackageParam lpparam) {
        int count = 0;
        String[] classes = {
            "com.oplus.omes.srp.SrpProviderModule",
            "com.oplus.omes.srp.SrpManager",
            "com.oplus.omes.srp.StdSrp",
            "com.oplus.omes.srp.SrpClient",
            "com.oplus.omes.srp.CryptoUtils",
            "com.oplus.omes.srp.AttestationUtils",
            "com.oplus.omes.msp.MspProviderModule",
            "com.oplus.msp.core.IntegrityChecker"
        };

        for (String cn : classes) {
            try {
                Class<?> cl = Class.forName(cn, false, lpparam.classLoader);
                for (Method m : cl.getDeclaredMethods()) {
                    try {
                        final String sig = cn + "." + m.getName();
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                Object r = p.getResult();
                                if (r instanceof Boolean && !(Boolean) r) {
                                    p.setResult(true);
                                    XposedBridge.log(TAG + ": [SRP] " + sig + " false->true");
                                } else if (r instanceof Integer && (Integer) r != 0) {
                                    p.setResult(0);
                                    XposedBridge.log(TAG + ": [SRP] " + sig + " " + r + "->0");
                                }
                            }
                        });
                    } catch (Throwable ignored) {}
                }
                count++;
            } catch (Throwable ignored) {}
        }
        XposedBridge.log(TAG + ": SRP hooked " + count + " classes");
    }

    // ==================== HEALTH ====================

    private void hookHealth(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === HEALTH ===");
        String[] classes = {
            "com.heytap.health.unlock.WatchUnlockManager",
            "com.heytap.health.watch.unlock.WatchUnlockHelper",
            "com.heytap.health.smartlock.SmartLockManager"
        };
        for (String cn : classes) {
            try {
                Class<?> cl = Class.forName(cn, false, lpparam.classLoader);
                for (Method m : cl.getDeclaredMethods()) {
                    String name = m.getName().toLowerCase();
                    if (name.contains("unlock") || name.contains("smartlock") || name.contains("trust")) {
                        try {
                            final String sig = cn + "." + m.getName();
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                    if (p.getResult() instanceof Boolean && !(Boolean) p.getResult()) {
                                        p.setResult(true);
                                        XposedBridge.log(TAG + ": [HEALTH] " + sig + " false->true");
                                    }
                                }
                            });
                        } catch (Throwable ignored) {}
                    }
                }
            } catch (Throwable ignored) {}
        }
    }
}
