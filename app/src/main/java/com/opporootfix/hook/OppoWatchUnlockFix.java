package com.opporootfix.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;

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
    // This is the main process we can hook. The sysintegrity process
    // (com.heytap.htms:sysintegrity) is a system_server child and
    // cannot be injected by LSPosed/Zygisk.

    private void hookLinker(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === LINKER: aggressive scan ===");

        hookCipher();
        hookJSONObjectSysIntegrity();
        hookAllClassesWithByteParams(lpparam);
        hookAllClassesWithIntegrityKeywords(lpparam);
        hookSendSecureData(lpparam);
        hookConnectionSocketMethods(lpparam);
        hookAllStringMethodsForErrorPatch(lpparam);
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
            XposedBridge.hookMethod(
                javax.crypto.Cipher.class.getMethod("doFinal"),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Throwable t = p.getThrowable();
                        if (t != null && (t.toString().contains("BadPadding") ||
                            t.toString().contains("BAD_DECRYPT"))) {
                            p.setThrowable(null);
                            p.setResult(new byte[0]);
                            XposedBridge.log(TAG + ": Cipher error intercepted (no-arg)");
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
                            XposedBridge.log(TAG + ": patched sysIntegrity (indent) -> true");
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
                            XposedBridge.log(TAG + ": getBoolean(sysIntegrity) -> true");
                        }
                    }
                });
            XposedBridge.hookMethod(
                org.json.JSONObject.class.getMethod("put", String.class, boolean.class),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        if ("sysIntegrity".equals(p.args[0]) && Boolean.FALSE.equals(p.args[1])) {
                            p.args[1] = true;
                            XposedBridge.log(TAG + ": put(sysIntegrity, false) -> true");
                        }
                    }
                });
            XposedBridge.log(TAG + ": Hooked JSONObject");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": JSONObject hook failed: " + t);
        }
    }

    private void hookAllClassesWithByteParams(XC_LoadPackage.LoadPackageParam lpparam) {
        int hookedCount = 0;
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses();
            for (Class<?> cl : loadedClasses) {
                for (Method m : cl.getDeclaredMethods()) {
                    Class<?>[] params = m.getParameterTypes();
                    boolean hasByteArray = false;
                    for (Class<?> p : params) {
                        if (p == byte[].class) { hasByteArray = true; break; }
                    }
                    if (!hasByteArray) continue;

                    String cn = cl.getName();
                    try {
                        final String sig = cn + "." + m.getName();
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                for (Object arg : p.args) {
                                    if (arg instanceof byte[]) {
                                        byte[] data = (byte[]) arg;
                                        if (data.length > 10) {
                                            XposedBridge.log(TAG + ": [BYTE-IN] " + sig + " len=" + data.length);
                                            logBytesIfRelevant(data, sig);
                                        }
                                    }
                                }
                            }

                            @Override
                            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                for (Object arg : p.args) {
                                    if (arg instanceof byte[]) {
                                        byte[] data = (byte[]) arg;
                                        if (data.length > 10) {
                                            XposedBridge.log(TAG + ": [BYTE-OUT] " + sig + " len=" + data.length);
                                            logBytesIfRelevant(data, sig);
                                        }
                                    }
                                }
                                Object result = p.getResult();
                                if (result instanceof byte[]) {
                                    byte[] data = (byte[]) result;
                                    if (data.length > 10) {
                                        XposedBridge.log(TAG + ": [BYTE-RET] " + sig + " len=" + data.length);
                                        logBytesIfRelevant(data, sig);
                                    }
                                }
                            }
                        });
                        hookedCount++;
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": byte scan error: " + t);
        }
        XposedBridge.log(TAG + ": byte-param classes hooked: " + hookedCount);
    }

    private void logBytesIfRelevant(byte[] data, String context) {
        try {
            String str = new String(data, "UTF-8");
            String lower = str.toLowerCase();
            if (lower.contains("integrity") || lower.contains("sysint") ||
                lower.contains("attest") || lower.contains("security") ||
                lower.contains("boot") || lower.contains("unlock")) {
                XposedBridge.log(TAG + ": [BYTE-RELEVANT] " + context + " contains keywords!");
                int searchLen = Math.min(data.length, 500);
                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < searchLen; i++) {
                    hex.append(String.format("%02x", data[i] & 0xFF));
                    if ((i + 1) % 32 == 0) hex.append("\n");
                }
                XposedBridge.log(TAG + ": [BYTE-HEX] " + context + ":\n" + hex.toString());
            }
        } catch (Throwable ignored) {}
    }

    private void hookAllClassesWithIntegrityKeywords(XC_LoadPackage.LoadPackageParam lpparam) {
        int hookedCount = 0;
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses();
            String[] keywords = {
                "integrity", "Integrity", "attest", "Attest",
                "srp", "Srp", "SRP", "msp", "Msp", "MSP",
                "stdsrp", "SysIntegrity", "SecurityLevel",
                "deviceintegrity", "DeviceIntegrity"
            };

            for (Class<?> cl : loadedClasses) {
                String cn = cl.getName();
                boolean match = false;
                for (String kw : keywords) {
                    if (cn.contains(kw)) { match = true; break; }
                }
                if (!match) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    try {
                        final String sig = cn + "." + m.getName();
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                Object r = p.getResult();
                                if (r instanceof Boolean && !(Boolean) r) {
                                    p.setResult(true);
                                    XposedBridge.log(TAG + ": [INT] " + sig + " false->true");
                                } else if (r instanceof Integer && (Integer) r != 0) {
                                    p.setResult(0);
                                    XposedBridge.log(TAG + ": [INT] " + sig + " " + r + "->0");
                                }
                            }
                        });
                        hookedCount++;
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": integrity scan error: " + t);
        }
        XposedBridge.log(TAG + ": integrity keyword classes hooked: " + hookedCount);
    }

    private void hookSendSecureData(XC_LoadPackage.LoadPackageParam lpparam) {
        int hookedCount = 0;
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses();
            for (Class<?> cl : loadedClasses) {
                String cn = cl.getName();
                if (!cn.contains("linker")) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    String name = m.getName().toLowerCase();
                    if (name.contains("sendscure") || name.contains("send_data") ||
                        name.contains("senddata") || name.contains("sendtoken") ||
                        name.contains("register")) {
                        try {
                            final String sig = cn + "." + m.getName();
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    StringBuilder sb = new StringBuilder();
                                    for (Object arg : p.args) {
                                        if (arg != null) {
                                            String s = arg.toString();
                                            sb.append(s.substring(0, Math.min(100, s.length()))).append(" | ");
                                        }
                                    }
                                    XposedBridge.log(TAG + ": [SEND>>] " + sig + " args: " + sb);
                                }

                                @Override
                                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                    XposedBridge.log(TAG + ": [SEND<<] " + sig + " result=" + p.getResult());
                                }
                            });
                            hookedCount++;
                            XposedBridge.log(TAG + ": Hooked " + sig);
                        } catch (Throwable ignored) {}
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": sendSecureData scan error: " + t);
        }
        XposedBridge.log(TAG + ": sendSecureData hooked: " + hookedCount);
    }

    private void hookConnectionSocketMethods(XC_LoadPackage.LoadPackageParam lpparam) {
        int hookedCount = 0;
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses();
            for (Class<?> cl : loadedClasses) {
                String cn = cl.getName();
                if (!cn.contains("ConnectionSocket") && !cn.contains("connectionsocket")) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    try {
                        final String sig = cn + "." + m.getName();
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                for (Object arg : p.args) {
                                    if (arg instanceof String) {
                                        String s = (String) arg;
                                        if (s.contains("errorCode") || s.contains("sysIntegrity") ||
                                            s.contains("unlock") || s.contains("token")) {
                                            XposedBridge.log(TAG + ": [SOCK>>] " + sig + " str=" +
                                                s.substring(0, Math.min(300, s.length())));
                                        }
                                    }
                                }
                            }

                            @Override
                            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                Throwable t = p.getThrowable();
                                if (t != null) {
                                    XposedBridge.log(TAG + ": [SOCK] " + sig + " threw: " + t);
                                    p.setThrowable(null);
                                }
                            }
                        });
                        hookedCount++;
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": ConnectionSocket scan error: " + t);
        }
        XposedBridge.log(TAG + ": ConnectionSocket hooked: " + hookedCount);
    }

    private void hookAllStringMethodsForErrorPatch(XC_LoadPackage.LoadPackageParam lpparam) {
        int hookedCount = 0;
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses();
            for (Class<?> cl : loadedClasses) {
                String cn = cl.getName();
                if (!cn.contains("linker")) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    String name = m.getName().toLowerCase();
                    if (name.contains("process") || name.contains("error") ||
                        name.contains("fail") || name.contains("result") ||
                        name.contains("response") || name.contains("callback")) {
                        Class<?>[] params = m.getParameterTypes();
                        for (Class<?> pt : params) {
                            if (pt == String.class) {
                                try {
                                    final String sig = cn + "." + m.getName();
                                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                                        @Override
                                        protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                            for (Object arg : p.args) {
                                                if (arg instanceof String) {
                                                    String s = (String) arg;
                                                    if (s.contains("errorCode") && s.contains("13")) {
                                                        XposedBridge.log(TAG + ": [ERR-PATCH] " + sig + " found errorCode=13");
                                                    }
                                                    if (s.contains("sysIntegrity") && s.contains("false")) {
                                                        String patched = s.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true");
                                                        XposedBridge.log(TAG + ": [ERR-PATCH] " + sig + " patched sysIntegrity");
                                                    }
                                                }
                                            }
                                        }
                                    });
                                    hookedCount++;
                                } catch (Throwable ignored) {}
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": error patch scan error: " + t);
        }
        XposedBridge.log(TAG + ": error patch hooked: " + hookedCount);
    }

    // ==================== HTMS PROCESS ====================
    // Best effort - this process may not be hookable (system_server child)

    private void hookHtms(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === HTMS proc=" + lpparam.processName + " ===");

        hookSystemProperties();
        hookBuildClass();
        hookAllMethodsInSrpClasses(lpparam);
        hookAllNativeMethods(lpparam);
        hookAllByteMethods(lpparam);
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
                        if (!"1".equals(val)) {
                            p.setResult("1");
                            XposedBridge.log(TAG + ": [PROP] " + key + " -> 1");
                        }
                    } else if (key.equals("ro.debuggable")) {
                        p.setResult("0");
                    } else if (key.equals("ro.secure")) {
                        p.setResult("1");
                    } else if (key.equals("ro.build.type")) {
                        if ("userdebug".equals(val) || "eng".equals(val)) {
                            p.setResult("user");
                        }
                    } else if (key.contains("selinux")) {
                        p.setResult("1");
                    } else if (key.contains("ro.adb.secure")) {
                        p.setResult("1");
                    }
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

    private void hookAllMethodsInSrpClasses(XC_LoadPackage.LoadPackageParam lpparam) {
        int count = 0;
        String[] classes = {
            "com.oplus.omes.srp.SrpProviderModule",
            "com.oplus.omes.srp.SrpManager",
            "com.oplus.omes.srp.StdSrp",
            "com.oplus.omes.srp.SrpClient",
            "com.oplus.omes.srp.CryptoUtils",
            "com.oplus.omes.srp.AttestationUtils",
            "com.oplus.omes.msp.MspProviderModule",
            "com.oplus.msp.core.IntegrityChecker",
            "com.heytap.htms.integrity.IntegrityService",
            "com.heytap.htms.integrity.IntegrityChecker",
            "com.heytap.htms.sysintegrity.IntegrityProvider",
            "com.oplus.omes.srp.provider.IntegrityProvider",
            "com.oplus.omes.srp.provider.DeviceIntegrityProvider"
        };

        for (String cn : classes) {
            Class<?> cl = findClass(cn, lpparam.classLoader);
            if (cl == null) continue;

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
                    count++;
                } catch (Throwable ignored) {}
            }
        }
        XposedBridge.log(TAG + ": SRP hooked " + count + " methods");
    }

    private void hookAllNativeMethods(XC_LoadPackage.LoadPackageParam lpparam) {
        int count = 0;
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses();
            for (Class<?> cl : loadedClasses) {
                String cn = cl.getName();
                if (!cn.contains("srp") && !cn.contains("Srp") &&
                    !cn.contains("msp") && !cn.contains("Msp") &&
                    !cn.contains("integrity") && !cn.contains("Integrity") &&
                    !cn.contains("stdsrp")) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    if (Modifier.isNative(m.getModifiers())) {
                        try {
                            final String sig = cn + "." + m.getName() + " [NATIVE]";
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                    Object r = p.getResult();
                                    XposedBridge.log(TAG + ": [NAT] " + sig + " ret=" +
                                        (r == null ? "null" : r.getClass().getSimpleName()));
                                    if (r instanceof Boolean && !(Boolean) r) { p.setResult(true); }
                                    else if (r instanceof Integer && (Integer) r != 0) { p.setResult(0); }
                                }
                            });
                            count++;
                        } catch (Throwable ignored) {}
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": native hook error: " + t);
        }
        XposedBridge.log(TAG + ": native hooked " + count + " methods");
    }

    private void hookAllByteMethods(XC_LoadPackage.LoadPackageParam lpparam) {
        int count = 0;
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses();
            for (Class<?> cl : loadedClasses) {
                String cn = cl.getName();
                if (!cn.contains("srp") && !cn.contains("Srp") &&
                    !cn.contains("msp") && !cn.contains("Msp") &&
                    !cn.contains("integrity") && !cn.contains("Integrity")) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    for (Class<?> pt : m.getParameterTypes()) {
                        if (pt == byte[].class) {
                            try {
                                final String sig = cn + "." + m.getName();
                                XposedBridge.hookMethod(m, new XC_MethodHook() {
                                    @Override
                                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                        for (Object arg : p.args) {
                                            if (arg instanceof byte[]) {
                                                byte[] data = (byte[]) arg;
                                                String str = new String(data, "UTF-8").toLowerCase();
                                                if (str.contains("integrity") || str.contains("sysint")) {
                                                    XposedBridge.log(TAG + ": [HTMS-BYTE] " + sig + " has integrity data, len=" + data.length);
                                                }
                                            }
                                        }
                                    }
                                });
                                count++;
                            } catch (Throwable ignored) {}
                            break;
                        }
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": byte hook error: " + t);
        }
        XposedBridge.log(TAG + ": htms byte hooked " + count + " methods");
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
            Class<?> cl = findClass(cn, lpparam.classLoader);
            if (cl == null) continue;
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
        }
    }

    // ==================== UTILITIES ====================

    private Class<?>[] getAllLoadedClasses() {
        try {
            Object at = XposedHelpers.callStaticMethod(
                Class.forName("android.app.ActivityThread"), "currentActivityThread");
            if (at == null) return new Class<?>[0];
            Object pkgs = XposedHelpers.getObjectField(at, "mPackages");
            if (pkgs == null) return new Class<?>[0];
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> map = (java.util.Map<String, Object>) pkgs;
            java.util.List<Class<?>> result = new java.util.ArrayList<>();
            for (Object val : map.values()) {
                Object cls = XposedHelpers.getObjectField(val, "mAppComponentFactory");
                if (cls != null) result.add(cls.getClass());
            }
            return result.toArray(new Class<?>[0]);
        } catch (Throwable t) {
            return new Class<?>[0];
        }
    }

    private Class<?> findClass(String cn, ClassLoader cl) {
        try {
            return XposedHelpers.findClass(cn, cl);
        } catch (Throwable t) {
            return null;
        }
    }
}
