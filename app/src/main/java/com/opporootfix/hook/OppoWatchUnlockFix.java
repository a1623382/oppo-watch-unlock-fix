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
        XposedBridge.log(TAG + ": === LINKER ===");

        hookCipher();
        hookProcessLockEventResponse(lpparam);
        hookSysIntegrityJson();
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

    private void hookProcessLockEventResponse(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] prefixes = {
            "com.oplus.linker.unlock",
            "com.oplus.linker"
        };
        String[] suffixes = {
            "ConnectionSocket", "a", "b", "c", "d", "e"
        };

        int found = 0;
        for (String prefix : prefixes) {
            for (String suffix : suffixes) {
                String cn = prefix + "." + suffix;
                Class<?> cl = findClass(cn, lpparam.classLoader);
                if (cl == null) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    String name = m.getName();
                    if (name.contains("processLockEvent") || name.contains("processLockInquiry")) {
                        try {
                            final String sig = cn + "." + name;
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    XposedBridge.log(TAG + ": >> " + sig);
                                    for (Object arg : p.args) {
                                        if (arg instanceof String) {
                                            String s = (String) arg;
                                            if (s.length() > 0) {
                                                XposedBridge.log(TAG + ": arg=" + s.substring(0, Math.min(200, s.length())));
                                            }
                                        }
                                    }
                                }

                                @Override
                                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                    Throwable t = p.getThrowable();
                                    if (t != null) {
                                        XposedBridge.log(TAG + ": " + sig + " threw: " + t);
                                        p.setThrowable(null);
                                    }
                                }
                            });
                            found++;
                            XposedBridge.log(TAG + ": Hooked " + sig);
                        } catch (Throwable ignored) {}
                    }
                }
            }
        }
        XposedBridge.log(TAG + ": processLockEvent hooked: " + found);
    }

    private void hookSysIntegrityJson() {
        try {
            XposedBridge.hookMethod(
                org.json.JSONObject.class.getMethod("toString"),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String s = (String) p.getResult();
                        if (s != null && s.contains("\"sysIntegrity\":false")) {
                            p.setResult(s.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true"));
                            XposedBridge.log(TAG + ": patched sysIntegrity in toString()");
                        }
                    }
                });
        } catch (Throwable t) {}
    }

    private void hookHtms(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === HTMS proc=" + lpparam.processName + " ===");

        hookSystemProperties();
        hookBuildClass();
        hookSrpProvider(lpparam);
        hookAllNativeMethods(lpparam);
        hookMspModule(lpparam);
        hookByteOutput(lpparam);
    }

    private void hookSystemProperties() {
        try {
            XposedBridge.hookMethod(
                android.os.SystemProperties.class.getMethod("get", String.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String key = (String) p.args[0];
                        String val = (String) p.getResult();
                        if (key == null) return;

                        if (key.contains("verifiedbootstate") || key.contains("flash.locked")) {
                            if (val == null || !val.equals("green") && !val.equals("1")) {
                                XposedBridge.log(TAG + ": [PROP] " + key + "=" + val + " -> " + (key.contains("locked") ? "1" : "green"));
                                p.setResult(key.contains("locked") ? "1" : "green");
                            }
                        } else if (key.equals("ro.boot.flash.locked")) {
                            p.setResult("1");
                            XposedBridge.log(TAG + ": [PROP] flash.locked -> 1");
                        } else if (key.equals("ro.boot.verifiedbootstate")) {
                            p.setResult("green");
                            XposedBridge.log(TAG + ": [PROP] verifiedbootstate -> green");
                        } else if (key.equals("ro.debuggable")) {
                            p.setResult("0");
                        } else if (key.equals("ro.secure")) {
                            p.setResult("1");
                        } else if (key.equals("ro.build.type")) {
                            if ("userdebug".equals(val) || "eng".equals(val)) {
                                p.setResult("user");
                                XposedBridge.log(TAG + ": [PROP] build.type -> user");
                            }
                        } else if (key.contains("ro.adb.secure")) {
                            p.setResult("1");
                        } else if (key.contains("selinux") || key.contains("ro.boot.selinux")) {
                            p.setResult("1");
                            XposedBridge.log(TAG + ": [PROP] selinux -> 1");
                        }
                    }
                });

            XposedBridge.hookMethod(
                android.os.SystemProperties.class.getMethod("get", String.class, String.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        String key = (String) p.args[0];
                        if (key == null) return;

                        if (key.equals("ro.boot.flash.locked")) {
                            p.setResult("1");
                        } else if (key.equals("ro.boot.verifiedbootstate")) {
                            p.setResult("green");
                        } else if (key.equals("ro.debuggable")) {
                            p.setResult("0");
                        } else if (key.equals("ro.secure")) {
                            p.setResult("1");
                        } else if (key.equals("ro.build.type")) {
                            String val = (String) p.getResult();
                            if ("userdebug".equals(val) || "eng".equals(val)) {
                                p.setResult("user");
                            }
                        } else if (key.contains("selinux")) {
                            p.setResult("1");
                        }
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

    private void hookSrpProvider(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] classes = {
            "com.oplus.omes.srp.SrpProviderModule",
            "com.oplus.omes.srp.SrpManager",
            "com.oplus.omes.msp.MspProviderModule",
            "com.oplus.msp.core.IntegrityChecker"
        };

        int count = 0;
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
        try {
            Class<?>[] loadedClasses = getAllLoadedClasses(lpparam.classLoader);
            int count = 0;

            for (Class<?> cl : loadedClasses) {
                String cn = cl.getName();
                if (!cn.contains("srp") && !cn.contains("Srp") &&
                    !cn.contains("msp") &&                     !cn.contains("Msp") &&
                    !cn.contains("integrity") && !cn.contains("Integrity") &&
                    !cn.contains("stdsrp")) continue;

                for (Method m : cl.getDeclaredMethods()) {
                    if (java.lang.reflect.Modifier.isNative(m.getModifiers())) {
                        try {
                            final String sig = cn + "." + m.getName() + " [NATIVE]";
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    XposedBridge.log(TAG + ": [NATIVE>>] " + sig);
                                }
                                @Override
                                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                    Object r = p.getResult();
                                    XposedBridge.log(TAG + ": [NATIVE<<] " + sig + " result=" +
                                        (r == null ? "null" : r.getClass().getSimpleName() + "(" + r.toString().substring(0, Math.min(100, r.toString().length())) + ")"));
                                    if (r instanceof Boolean && !(Boolean) r) {
                                        p.setResult(true);
                                    } else if (r instanceof Integer && (Integer) r != 0) {
                                        p.setResult(0);
                                    }
                                }
                            });
                            count++;
                        } catch (Throwable ignored) {}
                    }
                }
            }
            XposedBridge.log(TAG + ": Native method hooked: " + count);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Native hook error: " + t);
        }
    }

    private void hookMspModule(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] classes = {
            "com.heytap.htms.integrity.IntegrityService",
            "com.heytap.htms.integrity.IntegrityChecker",
            "com.heytap.htms.sysintegrity.IntegrityProvider",
            "com.oplus.omes.srp.provider.IntegrityProvider",
            "com.oplus.omes.srp.provider.DeviceIntegrityProvider",
            "com.oplus.omes.srp.AttestationUtils",
            "com.oplus.omes.srp.CryptoUtils",
            "com.oplus.omes.srp.StdSrp",
            "com.oplus.omes.srp.SrpClient"
        };

        int count = 0;
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
                                XposedBridge.log(TAG + ": [MSP] " + sig + " false->true");
                            } else if (r instanceof Integer && (Integer) r != 0) {
                                p.setResult(0);
                                XposedBridge.log(TAG + ": [MSP] " + sig + " " + r + "->0");
                            }
                        }
                    });
                    count++;
                } catch (Throwable ignored) {}
            }
        }
        XposedBridge.log(TAG + ": MSP hooked " + count + " methods");
    }

    private void hookByteOutput(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> cl = findClass("com.oplus.omes.srp.SrpProviderModule", lpparam.classLoader);
            if (cl == null) return;

            for (Method m : cl.getDeclaredMethods()) {
                for (Class<?> pt : m.getParameterTypes()) {
                    if (pt == byte[].class) {
                        try {
                            final String sig = "SrpProviderModule." + m.getName();
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    for (Object arg : p.args) {
                                        if (arg instanceof byte[]) {
                                            byte[] data = (byte[]) arg;
                                            XposedBridge.log(TAG + ": [BYTE] " + sig + " input len=" + data.length);
                                            for (int i = 0; i < data.length - 20; i++) {
                                                if (data[i] == 's' && data[i+1] == 'y' && data[i+2] == 's' &&
                                                    data[i+3] == 'I' && data[i+4] == 'n' && data[i+5] == 't') {
                                                    XposedBridge.log(TAG + ": [BYTE] Found 'sysInt' at offset " + i);
                                                    for (int j = i; j < Math.min(i + 30, data.length); j++) {
                                                        XposedBridge.log(TAG + ": [BYTE] offset " + j + " = " + (char)(data[j] & 0xFF) + " (0x" + Integer.toHexString(data[j] & 0xFF) + ")");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                @Override
                                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                    for (Object arg : p.args) {
                                        if (arg instanceof byte[]) {
                                            byte[] data = (byte[]) arg;
                                            String str = new String(data, "UTF-8").toLowerCase();
                                            if (str.contains("sysintegrity") || str.contains("integrity")) {
                                                XposedBridge.log(TAG + ": [BYTE] " + sig + " output contains integrity, len=" + data.length);
                                            }
                                        }
                                    }
                                }
                            });
                            break;
                        } catch (Throwable ignored) {}
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Byte hook error: " + t);
        }
    }

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

    private Class<?>[] getAllLoadedClasses(ClassLoader cl) {
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
                if (cls != null) {
                    result.add(cls.getClass());
                }
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
