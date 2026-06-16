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

    // ==================== LINKER PROCESS ====================

    private void hookLinker(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === LINKER v1.3.1 ===");

        hookCipher();
        hookJSONObjectSysIntegrity();
        hookClassForName(lpparam);
        hookClassLoaderLoadClass(lpparam);
        hookStringBuilderToString();
        hookMSPResponseInterceptor(lpparam);
    }

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

    // Hook Class.forName() to catch when linker loads classes we care about
    private void hookClassForName(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedBridge.hookMethod(
                Class.class.getMethod("forName", String.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String name = (String) p.args[0];
                        if (name == null) return;
                        Class<?> cl = (Class<?>) p.getResult();
                        if (cl == null) return;

                        String lower = name.toLowerCase();
                        if (lower.contains("connectionsocket") || lower.contains("connectionmanager") ||
                            lower.contains("encryptionutils") || lower.contains("protodatagenerator") ||
                            lower.contains("unlock") || lower.contains("srp") ||
                            lower.contains("msp") || lower.contains("integrity") ||
                            lower.contains("attestation") || lower.contains("token")) {

                            XposedBridge.log(TAG + ": [FORNAME] " + name + " -> hooking methods");
                            hookAllMethodsOfClass(cl, name);
                        }
                    }
                });

            XposedBridge.hookMethod(
                Class.class.getMethod("forName", String.class, boolean.class, ClassLoader.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String name = (String) p.args[0];
                        if (name == null) return;
                        Class<?> cl = (Class<?>) p.getResult();
                        if (cl == null) return;

                        String lower = name.toLowerCase();
                        if (lower.contains("connectionsocket") || lower.contains("connectionmanager") ||
                            lower.contains("encryptionutils") || lower.contains("protodatagenerator") ||
                            lower.contains("unlock") || lower.contains("srp") ||
                            lower.contains("msp") || lower.contains("integrity") ||
                            lower.contains("attestation") || lower.contains("token")) {

                            XposedBridge.log(TAG + ": [FORNAME2] " + name + " -> hooking methods");
                            hookAllMethodsOfClass(cl, name);
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked Class.forName");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Class.forName hook failed: " + t);
        }
    }

    // Hook ClassLoader.loadClass() to catch obfuscated class loading
    private void hookClassLoaderLoadClass(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> baseClClass = Class.forName("java.lang.ClassLoader");
            XposedBridge.hookMethod(
                baseClClass.getMethod("loadClass", String.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String name = (String) p.args[0];
                        if (name == null) return;
                        Class<?> cl = (Class<?>) p.getResult();
                        if (cl == null) return;

                        String lower = name.toLowerCase();
                        if (lower.contains("connectionsocket") || lower.contains("connectionmanager") ||
                            lower.contains("encryptionutils") || lower.contains("protodatagenerator") ||
                            lower.contains("unlock") || lower.contains("srp") ||
                            lower.contains("msp") || lower.contains("integrity")) {

                            XposedBridge.log(TAG + ": [LOADCLASS] " + name);
                            hookAllMethodsOfClass(cl, name);
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked ClassLoader.loadClass");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": ClassLoader hook failed: " + t);
        }
    }

    // Hook StringBuilder.toString() to trace data construction
    private void hookStringBuilderToString() {
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
                            XposedBridge.log(TAG + ": [SB] patched sysIntegrity in StringBuilder");
                        }

                        if (s.contains("errorCode") && s.contains("13")) {
                            XposedBridge.log(TAG + ": [SB] found errorCode=13 in StringBuilder");
                            // Log stack trace to find where this is constructed
                            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                            StringBuilder trace = new StringBuilder();
                            for (int i = 3; i < Math.min(stack.length, 8); i++) {
                                trace.append(stack[i].toString()).append("\n");
                            }
                            XposedBridge.log(TAG + ": [SB] stack:\n" + trace.toString());
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked StringBuilder.toString");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": StringBuilder hook failed: " + t);
        }
    }

    // Hook all methods that take byte[] or return byte[] - trace MSP IPC data
    private void hookMSPResponseInterceptor(XC_LoadPackage.LoadPackageParam lpparam) {
        int count = 0;
        try {
            // Scan all loaded classes via pathList/dexElements
            ClassLoader cl = lpparam.classLoader;
            Object pathList = XposedHelpers.getObjectField(cl, "pathList");
            if (pathList != null) {
                Object[] dexElements = (Object[]) XposedHelpers.getObjectField(pathList, "dexElements");
                if (dexElements != null) {
                    for (Object element : dexElements) {
                        Object dexFile = XposedHelpers.getObjectField(element, "dexFile");
                        if (dexFile == null) continue;

                        java.util.Enumeration<String> entries = (java.util.Enumeration<String>)
                            XposedHelpers.callMethod(dexFile, "entries");

                        while (entries.hasMoreElements()) {
                            String className = entries.nextElement();
                            if (className == null) continue;
                            String lower = className.toLowerCase();

                            if (lower.contains("connection") || lower.contains("socket") ||
                                lower.contains("manager") || lower.contains("encrypt") ||
                                lower.contains("proto") || lower.contains("unlock") ||
                                lower.contains("token") || lower.contains("srp") ||
                                lower.contains("msp") || lower.contains("integrity") ||
                                lower.contains("attest") || lower.contains("linker")) {

                                try {
                                    Class<?> clazz = Class.forName(className, false, cl);
                                    hookAllMethodsOfClass(clazz, className);
                                    count++;
                                } catch (Throwable ignored) {}
                            }
                        }
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": MSP scan error: " + t);
        }
        XposedBridge.log(TAG + ": MSP scanned and hooked " + count + " classes");
    }

    private void hookAllMethodsOfClass(Class<?> clazz, String className) {
        try {
            for (Method m : clazz.getDeclaredMethods()) {
                try {
                    final String sig = className + "." + m.getName();
                    Class<?>[] paramTypes = m.getParameterTypes();
                    final boolean hasByteArray;
                    final boolean hasString;
                    boolean hb = false, hs = false;
                    for (Class<?> pt : paramTypes) {
                        if (pt == byte[].class) hb = true;
                        if (pt == String.class) hs = true;
                    }
                    hasByteArray = hb;
                    hasString = hs;

                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                            if (hasByteArray) {
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
                            if (hasString) {
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
                            } else if (result instanceof String) {
                                String s = (String) result;
                                if (s.contains("errorCode") || s.contains("sysIntegrity")) {
                                    XposedBridge.log(TAG + ": [STR<<] " + sig + " ret=" +
                                        s.substring(0, Math.min(200, s.length())));
                                }
                            }
                        }
                    });
                } catch (Throwable ignored) {}
            }
        } catch (Throwable t) {}
    }

    private void logRelevantBytes(byte[] data, String context) {
        try {
            String str = new String(data, "UTF-8");
            String lower = str.toLowerCase();
            if (lower.contains("integrity") || lower.contains("sysint") ||
                lower.contains("attest") || lower.contains("boot") ||
                lower.contains("security") || lower.contains("unlock")) {
                XposedBridge.log(TAG + ": [BYTE-KEY] " + context + " has relevant data!");
                StringBuilder hex = new StringBuilder();
                int limit = Math.min(data.length, 200);
                for (int i = 0; i < limit; i++) {
                    hex.append(String.format("%02x", data[i] & 0xFF));
                    if ((i + 1) % 32 == 0) hex.append("\n");
                }
                XposedBridge.log(TAG + ": [BYTE-HEX] " + hex.toString());
            }
        } catch (Throwable ignored) {}
    }

    // ==================== HTMS PROCESS (best effort) ====================

    private void hookHtms(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === HTMS proc=" + lpparam.processName + " ===");
        hookSystemProperties();
        hookBuildClass();
        hookAllKnownSrpClasses(lpparam);
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

    private void hookAllKnownSrpClasses(XC_LoadPackage.LoadPackageParam lpparam) {
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
                hookAllMethodsOfClass(cl, cn);
                count++;
            } catch (Throwable ignored) {}
        }
        XposedBridge.log(TAG + ": SRP hooked " + count + " known classes");
    }

    // ==================== HEALTH PROCESS ====================

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
                hookAllMethodsOfClass(cl, cn);
            } catch (Throwable ignored) {}
        }
    }
}
