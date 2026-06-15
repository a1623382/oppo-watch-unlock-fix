package com.opporootfix.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

public class OppoWatchUnlockFix implements IXposedHookLoadPackage {

    private static final String TAG = "OPPOWatchFix";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        String pkgName = lpparam.packageName;
        XposedBridge.log(TAG + ": Loaded pkg=" + pkgName + " process=" + lpparam.processName);

        if ("com.oplus.linker".equals(pkgName)) {
            hookLinkerApp(lpparam);
        } else if (pkgName.startsWith("com.heytap.htms")) {
            hookHtmsProcess(lpparam);
        } else if ("com.heytap.health".equals(pkgName)) {
            hookHealthApp(lpparam);
        }
    }

    private void hookLinkerApp(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === Hooking com.oplus.linker ===");

        hookCipherDecrypt();
        hookJSONObjectSysIntegrity(lpparam);
        hookUnlockResponseByScan(lpparam);
    }

    private void hookCipherDecrypt() {
        try {
            XposedBridge.hookMethod(
                javax.crypto.Cipher.class.getMethod("doFinal", byte[].class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Throwable t = param.getThrowable();
                        if (t != null && (t.toString().contains("BadPadding") ||
                            t.toString().contains("BAD_DECRYPT") ||
                            t.toString().contains("IllegalBlockSize"))) {
                            XposedBridge.log(TAG + ": Cipher error intercepted: " + t);
                            param.setThrowable(null);
                            param.setResult(new byte[0]);
                        }
                    }
                }
            );
            XposedBridge.log(TAG + ": Hooked Cipher.doFinal");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Cipher hook failed: " + t.getMessage());
        }
    }

    private void hookJSONObjectSysIntegrity(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> jsonObjClass = org.json.JSONObject.class;

            XposedBridge.hookMethod(
                jsonObjClass.getMethod("getBoolean", String.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if ("sysIntegrity".equals(param.args[0]) && Boolean.FALSE.equals(param.getResult())) {
                            param.setResult(true);
                            XposedBridge.log(TAG + ": JSONObject.getBoolean(sysIntegrity) -> true");
                        }
                    }
                }
            );

            XposedBridge.hookMethod(
                jsonObjClass.getMethod("optBoolean", String.class, boolean.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if ("sysIntegrity".equals(param.args[0]) && !(Boolean) param.getResult()) {
                            param.setResult(true);
                            XposedBridge.log(TAG + ": JSONObject.optBoolean(sysIntegrity) -> true");
                        }
                    }
                }
            );

            XposedBridge.hookMethod(
                jsonObjClass.getMethod("optBoolean", String.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if ("sysIntegrity".equals(param.args[0]) && Boolean.FALSE.equals(param.getResult())) {
                            param.setResult(true);
                            XposedBridge.log(TAG + ": JSONObject.optBoolean2(sysIntegrity) -> true");
                        }
                    }
                }
            );

            XposedBridge.hookMethod(
                jsonObjClass.getMethod("put", String.class, boolean.class),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if ("sysIntegrity".equals(param.args[0]) && Boolean.FALSE.equals(param.args[1])) {
                            param.args[1] = true;
                            XposedBridge.log(TAG + ": JSONObject.put(sysIntegrity, false) -> true");
                        }
                    }
                }
            );

            XposedBridge.hookMethod(
                jsonObjClass.getMethod("toString"),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        String result = (String) param.getResult();
                        if (result != null && result.contains("\"sysIntegrity\":false")) {
                            result = result.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true");
                            param.setResult(result);
                            XposedBridge.log(TAG + ": JSONObject.toString() patched sysIntegrity -> true");
                        }
                    }
                }
            );

            XposedBridge.hookMethod(
                jsonObjClass.getMethod("toString", int.class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        String result = (String) param.getResult();
                        if (result != null && result.contains("\"sysIntegrity\":false")) {
                            result = result.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true");
                            param.setResult(result);
                            XposedBridge.log(TAG + ": JSONObject.toString(indent) patched sysIntegrity -> true");
                        }
                    }
                }
            );

            XposedBridge.log(TAG + ": Hooked JSONObject for sysIntegrity patching");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": JSONObject hook failed: " + t.getMessage());
        }
    }

    private void hookUnlockResponseByScan(XC_LoadPackage.LoadPackageParam lpparam) {
        int hookedCount = 0;
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object at = XposedHelpers.callStaticMethod(atClass, "currentActivityThread");
            if (at == null) return;

            java.io.File dataDir = new java.io.File("/data/data/com.oplus.linker");
            if (!dataDir.exists()) {
                dataDir = new java.io.File("/data/user/0/com.oplus.linker");
            }

            ClassLoader cl = lpparam.classLoader;
            String[] knownPrefixes = {
                "com.oplus.linker.unlock",
                "com.oplus.linker.crypto",
                "com.oplus.linker.integrity",
                "com.oplus.linker.socket",
                "com.oplus.linker.srp",
                "com.oplus.linker"
            };

            for (String prefix : knownPrefixes) {
                String[][] suffixes = {
                    {"ConnectionSocket"}, {"ConnectionManager"}, {"UnlockManager"},
                    {"EncryptionUtils"}, {"ProtoDataGenerator"}, {"WatchUnlockManager"},
                    {"UnlockHelper"}, {"IntegrityChecker"}, {"SrpUtils"},
                    {"AttestationUtils"}, {"PhoneUnlockWatchManager"},
                    {"SmartLockManager"}, {"TokenManager"}
                };

                for (String[] suffix : suffixes) {
                    String className = prefix + "." + suffix[0];
                    Class<?> clazz = findClass(className, cl);
                    if (clazz == null) continue;

                    for (Method method : clazz.getDeclaredMethods()) {
                        String name = method.getName();
                        boolean match = name.contains("processLock") ||
                                       name.contains("LockEvent") ||
                                       name.contains("lockEvent") ||
                                       name.contains("sendSecure") ||
                                       name.contains("unlock") ||
                                       name.contains("Unlock") ||
                                       name.contains("processToken") ||
                                       name.contains("fail") ||
                                       name.contains("error");

                        if (match) {
                            try {
                                final String mSig = className + "." + name + "(" + getParamTypes(method) + ")";
                                XposedBridge.hookMethod(method, new XC_MethodHook() {
                                    @Override
                                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                        Throwable t = param.getThrowable();
                                        if (t != null) {
                                            XposedBridge.log(TAG + ": [SCAN] " + mSig + " threw: " + t);
                                            param.setThrowable(null);
                                        }
                                        for (Object arg : param.args) {
                                            if (arg instanceof String) {
                                                String s = (String) arg;
                                                if (s.contains("errorCode") || s.contains("sysIntegrity") ||
                                                    s.contains("fail") || s.contains("unlock")) {
                                                    XposedBridge.log(TAG + ": [SCAN] " + mSig + " strArg: " +
                                                        s.substring(0, Math.min(300, s.length())));
                                                }
                                            }
                                        }
                                    }
                                });
                                hookedCount++;
                                XposedBridge.log(TAG + ": [SCAN] Hooked " + mSig);
                            } catch (Throwable ignored) {}
                        }
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Scan error: " + t.getMessage());
        }
        XposedBridge.log(TAG + ": Scan hooked " + hookedCount + " methods in linker");
    }

    private void hookHtmsProcess(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === Hooking htms process: " + lpparam.processName + " ===");

        hookSrpClasses(lpparam);
        hookAllIntegrityClasses(lpparam);
        hookNativeCallbacks(lpparam);
    }

    private void hookSrpClasses(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] srpClasses = {
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

        int hookedCount = 0;
        for (String className : srpClasses) {
            Class<?> clazz = findClass(className, lpparam.classLoader);
            if (clazz == null) continue;

            for (Method method : clazz.getDeclaredMethods()) {
                try {
                    final String mFullName = className + "." + method.getName();
                    XposedBridge.hookMethod(method, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            Object result = param.getResult();
                            if (result instanceof Boolean) {
                                boolean val = (Boolean) result;
                                if (!val) {
                                    param.setResult(true);
                                    XposedBridge.log(TAG + ": [SRP] " + mFullName + " false->true");
                                }
                            } else if (result instanceof Integer) {
                                int val = (Integer) result;
                                if (val != 0) {
                                    param.setResult(0);
                                    XposedBridge.log(TAG + ": [SRP] " + mFullName + " " + val + "->0");
                                }
                            }
                        }
                    });
                    hookedCount++;
                } catch (Throwable ignored) {}
            }
        }
        XposedBridge.log(TAG + ": SRP hooked " + hookedCount + " methods");
    }

    private void hookAllIntegrityClasses(XC_LoadPackage.LoadPackageParam lpparam) {
        int hookedCount = 0;
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object at = XposedHelpers.callStaticMethod(atClass, "currentActivityThread");
            if (at == null) return;

            java.util.List<String> targetClasses = new java.util.ArrayList<>();
            String[] srpPrefixes = {
                "com.oplus.omes.srp", "com.oplus.omes.msp", "com.oplus.msp",
                "com.heytap.htms", "com.heytap.msp"
            };
            String[] srpSuffixes = {
                "integrity", "Integrity", "attest", "Attest", "verify", "Verify",
                "check", "Check", "srp", "Srp", "SRP", "msp", "Msp", "MSP",
                "provider", "Provider", "token", "Token", "device", "Device"
            };

            for (String prefix : srpPrefixes) {
                for (String suffix : srpSuffixes) {
                    String base = prefix + "." + suffix;
                    for (int i = 0; i < 10; i++) {
                        String className = base;
                        if (i > 0) className = base + "$" + (char)('a' + i - 1);
                        Class<?> clazz = findClass(className, lpparam.classLoader);
                        if (clazz != null) targetClasses.add(className);
                    }
                }
            }

            for (String className : targetClasses) {
                Class<?> clazz = findClass(className, lpparam.classLoader);
                if (clazz == null) continue;

                for (Method method : clazz.getDeclaredMethods()) {
                    try {
                        final String mFullName = className + "." + method.getName();
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object result = param.getResult();
                                if (result instanceof Boolean && !(Boolean) result) {
                                    param.setResult(true);
                                    XposedBridge.log(TAG + ": [INT] " + mFullName + " false->true");
                                } else if (result instanceof Integer && (Integer) result != 0) {
                                    param.setResult(0);
                                    XposedBridge.log(TAG + ": [INT] " + mFullName + " " + result + "->0");
                                }
                            }
                        });
                        hookedCount++;
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Integrity scan error: " + t.getMessage());
        }
        XposedBridge.log(TAG + ": Integrity scan hooked " + hookedCount + " methods");
    }

    private void hookNativeCallbacks(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> sysIntegrityClass = findClass("com.oplus.omes.srp.SrpProviderModule", lpparam.classLoader);
            if (sysIntegrityClass == null) return;

            for (Method method : sysIntegrityClass.getDeclaredMethods()) {
                Class<?>[] paramTypes = method.getParameterTypes();
                for (Class<?> pt : paramTypes) {
                    if (pt == byte[].class) {
                        final String mFullName = "SrpProviderModule." + method.getName();
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                for (int i = 0; i < param.args.length; i++) {
                                    if (param.args[i] instanceof byte[]) {
                                        byte[] data = (byte[]) param.args[i];
                                        String str = new String(data, "UTF-8");
                                        if (str.contains("sysIntegrity")) {
                                            XposedBridge.log(TAG + ": [NATIVE] " + mFullName + " byteArg contains sysIntegrity, len=" + data.length);
                                        }
                                    }
                                }
                            }
                        });
                        XposedBridge.log(TAG + ": [NATIVE] Hooked " + mFullName);
                        break;
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Native callback hook error: " + t.getMessage());
        }
    }

    private void hookHealthApp(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": === Hooking com.heytap.health ===");

        String[] classNames = {
            "com.heytap.health.unlock.WatchUnlockManager",
            "com.heytap.health.watch.unlock.WatchUnlockHelper",
            "com.heytap.health.smartlock.SmartLockManager"
        };

        for (String className : classNames) {
            Class<?> clazz = findClass(className, lpparam.classLoader);
            if (clazz == null) continue;

            for (Method method : clazz.getDeclaredMethods()) {
                String name = method.getName().toLowerCase();
                if (name.contains("unlock") || name.contains("smartlock") || name.contains("trust")) {
                    try {
                        final String mFullName = className + "." + method.getName();
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object result = param.getResult();
                                if (result instanceof Boolean && !(Boolean) result) {
                                    param.setResult(true);
                                    XposedBridge.log(TAG + ": [HEALTH] " + mFullName + " false->true");
                                }
                            }
                        });
                        XposedBridge.log(TAG + ": Hooked " + mFullName);
                    } catch (Throwable ignored) {}
                }
            }
        }
    }

    private Class<?> findClass(String className, ClassLoader cl) {
        try {
            return XposedHelpers.findClass(className, cl);
        } catch (Throwable t) {
            return null;
        }
    }

    private String getParamTypes(Method method) {
        StringBuilder sb = new StringBuilder();
        Class<?>[] types = method.getParameterTypes();
        for (int i = 0; i < types.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(types[i].getSimpleName());
        }
        return sb.toString();
    }
}
