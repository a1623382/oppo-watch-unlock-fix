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
        hookEncryptionUtils(lpparam);
    }

    // ==================== LINKER ====================

    private void hookCipher() {
        try {
            XposedBridge.hookMethod(
                javax.crypto.Cipher.class.getMethod("doFinal", byte[].class),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        byte[] input = (byte[]) p.args[0];
                        if (input == null || input.length < 10) return;

                        try {
                            String str = new String(input, "UTF-8");
                            if (str.contains("sysIntegrity")) {
                                XposedBridge.log(TAG + ": [CIPHER-IN] len=" + input.length +
                                    " contains sysIntegrity!");
                                XposedBridge.log(TAG + ": [CIPHER-ASCII] " +
                                    new String(input, "UTF-8").substring(0,
                                    Math.min(500, input.length)));

                                if (str.contains("sysIntegrity\":false")) {
                                    String patched = str.replace("sysIntegrity\":false",
                                        "sysIntegrity\":true");
                                    byte[] patchedBytes = patched.getBytes("UTF-8");
                                    System.arraycopy(patchedBytes, 0, input, 0,
                                        Math.min(patchedBytes.length, input.length));
                                    XposedBridge.log(TAG + ": [CIPHER-MOD] patched sysIntegrity in plaintext!");
                                }
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
            "com.oplus.linker.unlock.connect",
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
                    XposedBridge.log(TAG + ": Found and hooked " + cn);
                } catch (Throwable ignored) {}
            }
        }

        hookConnectionSocketDirect(lpparam);
        XposedBridge.log(TAG + ": Known classes hooked: " + count);
    }

    private void hookConnectionSocketDirect(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String cn = "com.oplus.linker.unlock.connect.ConnectionSocket";
            Class<?> cl = Class.forName(cn, false, lpparam.classLoader);
            XposedBridge.log(TAG + ": [DIRECT] Found ConnectionSocket");

            for (Method m : cl.getDeclaredMethods()) {
                try {
                    final String sig = cn + "." + m.getName();
                    boolean isProcessLockEvent = m.getName().contains("processLockEvent");
                    boolean isOnReceive = m.getName().equals("onReceive");

                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                            StringBuilder args = new StringBuilder();
                            for (Object arg : p.args) {
                                if (arg == null) {
                                    args.append("null");
                                } else if (arg instanceof byte[]) {
                                    byte[] data = (byte[]) arg;
                                    args.append("byte[").append(data.length).append("]");

                                    if (isProcessLockEvent) {
                                        XposedBridge.log(TAG + ": [HEX] " + sig + " hex=" + bytesToHex(data));
                                    }

                                    if (data.length > 100) {
                                        logRelevantBytes(data, sig);
                                    }
                                } else if (arg instanceof String) {
                                    String s = (String) arg;
                                    args.append("\"").append(s.substring(0, Math.min(100, s.length()))).append("\"");
                                } else {
                                    args.append(arg.getClass().getSimpleName()).append("@").append(Integer.toHexString(arg.hashCode()));
                                }
                                args.append(", ");
                            }
                            XposedBridge.log(TAG + ": [>>] " + sig + "(" + args + ")");
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                            Throwable t = p.getThrowable();
                            if (t != null) {
                                XposedBridge.log(TAG + ": [THREW] " + sig + ": " + t);
                                p.setThrowable(null);
                            }
                            Object r = p.getResult();
                            if (r != null) {
                                String rStr = r.toString();
                                XposedBridge.log(TAG + ": [<<] " + sig + " = " + r.getClass().getSimpleName() +
                                    "(" + rStr.substring(0, Math.min(100, rStr.length())) + ")");
                            }
                        }
                    });
                } catch (Throwable ignored) {}
            }

            hookConnectionManagerSecureSend(lpparam);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": [DIRECT] ConnectionSocket not found: " + t);
        }
    }

    private void hookConnectionManagerSecureSend(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String cn = "com.oplus.linker.unlock.connect.ConnectionManager";
            Class<?> cl = Class.forName(cn, false, lpparam.classLoader);
            XposedBridge.log(TAG + ": [DIRECT] Found ConnectionManager");

            for (Method m : cl.getDeclaredMethods()) {
                String name = m.getName();
                if (!name.contains("sendSecure") && !name.contains("secureSend")) continue;

                Class<?>[] params = m.getParameterTypes();
                boolean hasByteArray = false;
                boolean hasString = false;
                for (Class<?> pt : params) {
                    if (pt == byte[].class) hasByteArray = true;
                    if (pt == String.class) hasString = true;
                }
                if (!hasByteArray) continue;

                final String sig = cn + "." + name;
                final int byteArrayIndex;
                final int stringIndex;
                int bi = -1, si = -1;
                for (int i = 0; i < params.length; i++) {
                    if (params[i] == byte[].class && bi == -1) bi = i;
                    if (params[i] == String.class && si == -1) si = i;
                }
                byteArrayIndex = bi;
                stringIndex = si;

                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        String op = stringIndex >= 0 && p.args[stringIndex] != null ?
                            (String) p.args[stringIndex] : "unknown";

                        if (byteArrayIndex >= 0 && p.args[byteArrayIndex] instanceof byte[]) {
                            byte[] data = (byte[]) p.args[byteArrayIndex];
                            XposedBridge.log(TAG + ": [SEND] " + op + " len=" + data.length);

                            if (op.contains("unlock")) {
                                XposedBridge.log(TAG + ": [SEND-UNLOCK] hex=" + bytesToHex(data));
                                modifyUnlockPayload(data);
                            }
                        }
                    }
                });
                XposedBridge.log(TAG + ": Hooked " + sig);
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": ConnectionManager hook failed: " + t);
        }
    }

    private void modifyUnlockPayload(byte[] data) {
        try {
            String str = new String(data, "UTF-8");

            int count = 0;
            if (str.contains("\"sysIntegrity\":false")) {
                String modified = str.replace("\"sysIntegrity\":false", "\"sysIntegrity\":true");
                byte[] modifiedBytes = modified.getBytes("UTF-8");
                System.arraycopy(modifiedBytes, 0, data, 0, Math.min(modifiedBytes.length, data.length));
                count++;
                XposedBridge.log(TAG + ": [MOD] patched sysIntegrity in payload");
            }

            if (str.contains("sysIntegrity\\\":false")) {
                String modified = str.replace("sysIntegrity\\\":false", "sysIntegrity\\\":true");
                byte[] modifiedBytes = modified.getBytes("UTF-8");
                System.arraycopy(modifiedBytes, 0, data, 0, Math.min(modifiedBytes.length, data.length));
                count++;
                XposedBridge.log(TAG + ": [MOD] patched escaped sysIntegrity in payload");
            }

            XposedBridge.log(TAG + ": [MOD] payload modifications: " + count);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": [MOD] error: " + t);
        }
    }

    private void hookEncryptionUtils(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] classNames = {
            "com.oplus.linker.unlock.utils.EncryptionUtils",
            "com.oplus.linker.crypto.EncryptionUtils",
            "com.oplus.linker.EncryptionUtils",
            "com.oplus.linker.utils.EncryptionUtils"
        };

        int hookedCount = 0;
        for (String cn : classNames) {
            try {
                Class<?> cl = Class.forName(cn, false, lpparam.classLoader);
                XposedBridge.log(TAG + ": [CRYPTO] Found " + cn);

                for (Method m : cl.getDeclaredMethods()) {
                    try {
                        final String sig = cn + "." + m.getName();
                        Class<?>[] params = m.getParameterTypes();

                        boolean hasByteArray = false;
                        for (Class<?> pt : params) {
                            if (pt == byte[].class) { hasByteArray = true; break; }
                        }

                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                StringBuilder args = new StringBuilder();
                                for (int i = 0; i < p.args.length; i++) {
                                    Object arg = p.args[i];
                                    if (arg == null) {
                                        args.append("null");
                                    } else if (arg instanceof byte[]) {
                                        byte[] data = (byte[]) arg;
                                        args.append("byte[").append(data.length).append("]");
                                        if (data.length > 10) {
                                            XposedBridge.log(TAG + ": [CRYPTO-IN] " + sig + " arg" + i + " hex=" + bytesToHex(data));
                                            logProtobufKeywords(data, sig);
                                        }
                                    } else {
                                        args.append(arg.getClass().getSimpleName());
                                    }
                                    args.append(", ");
                                }
                                XposedBridge.log(TAG + ": [CRYPTO>>] " + sig + "(" + args + ")");
                            }

                            @Override
                            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                Throwable t = p.getThrowable();
                                if (t != null) {
                                    XposedBridge.log(TAG + ": [CRYPTO-ERR] " + sig + " threw: " + t);
                                    p.setThrowable(null);
                                }
                                Object r = p.getResult();
                                if (r instanceof byte[]) {
                                    byte[] data = (byte[]) r;
                                    XposedBridge.log(TAG + ": [CRYPTO-OUT] " + sig + " ret byte[" + data.length + "] hex=" + bytesToHex(data));
                                    logProtobufKeywords(data, sig);
                                } else if (r != null) {
                                    XposedBridge.log(TAG + ": [CRYPTO-OUT] " + sig + " ret=" + r.getClass().getSimpleName());
                                }
                            }
                        });
                        hookedCount++;
                        XposedBridge.log(TAG + ": [CRYPTO] Hooked " + sig);
                    } catch (Throwable ignored) {}
                }
                break;
            } catch (Throwable ignored) {}
        }
        XposedBridge.log(TAG + ": [CRYPTO] hooked " + hookedCount + " methods");

        hookEncryptionUtilsByScan(lpparam);
    }

    private void hookEncryptionUtilsByScan(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> cl = Class.forName("android.app.ActivityThread", false, null);
            Object at = XposedHelpers.callStaticMethod(cl, "currentActivityThread");
            if (at == null) return;
            Object pkgs = XposedHelpers.getObjectField(at, "mPackages");
            if (pkgs == null) return;

            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> map = (java.util.Map<String, Object>) pkgs;
            for (Object val : map.values()) {
                try {
                    ClassLoader classLoader = (ClassLoader) XposedHelpers.getObjectField(
                        XposedHelpers.getObjectField(val, "mInfo"), "mClassloader");
                    if (classLoader == null) continue;

                    Object pathList = XposedHelpers.getObjectField(classLoader, "pathList");
                    if (pathList == null) continue;
                    Object[] dexElements = (Object[]) XposedHelpers.getObjectField(pathList, "dexElements");
                    if (dexElements == null) continue;

                    for (Object element : dexElements) {
                        Object dexFile = XposedHelpers.getObjectField(element, "dexFile");
                        if (dexFile == null) continue;

                        java.util.Enumeration<String> entries = (java.util.Enumeration<String>)
                            XposedHelpers.callMethod(dexFile, "entries");

                        while (entries.hasMoreElements()) {
                            String className = entries.nextElement();
                            if (className == null) continue;
                            String lower = className.toLowerCase();

                            if (lower.contains("encrypt") && lower.contains("util")) {
                                try {
                                    Class<?> clazz = Class.forName(className, false, classLoader);
                                    XposedBridge.log(TAG + ": [SCAN-ENC] Found: " + className);
                                    for (Method m : clazz.getDeclaredMethods()) {
                                        Class<?>[] pts = m.getParameterTypes();
                                        for (Class<?> pt : pts) {
                                            if (pt == byte[].class) {
                                                try {
                                                    final String sig = className + "." + m.getName();
                                                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                                                        @Override
                                                        protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                                            for (Object arg : p.args) {
                                                                if (arg instanceof byte[]) {
                                                                    byte[] data = (byte[]) arg;
                                                                    if (data.length > 10) {
                                                                        XposedBridge.log(TAG + ": [SCAN-BYTE] " + sig + " len=" + data.length);
                                                                        logProtobufKeywords(data, sig);
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        @Override
                                                        protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                                            Object r = p.getResult();
                                                            if (r instanceof byte[]) {
                                                                byte[] data = (byte[]) r;
                                                                XposedBridge.log(TAG + ": [SCAN-RET] " + sig + " ret len=" + data.length);
                                                                logProtobufKeywords(data, sig);
                                                            }
                                                        }
                                                    });
                                                    XposedBridge.log(TAG + ": [SCAN-ENC] Hooked " + sig);
                                                } catch (Throwable ignored) {}
                                                break;
                                            }
                                        }
                                    }
                                } catch (Throwable ignored) {}
                            }
                        }
                    }
                } catch (Throwable ignored) {}
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": [SCAN-ENC] error: " + t);
        }
    }

    private void logProtobufKeywords(byte[] data, String context) {
        try {
            String str = new String(data, "UTF-8");
            String lower = str.toLowerCase();
            if (lower.contains("integrity") || lower.contains("sysint") ||
                lower.contains("attest") || lower.contains("boot") ||
                lower.contains("security") || lower.contains("unlock") ||
                lower.contains("signature") || lower.contains("token")) {
                XposedBridge.log(TAG + ": [PROTO-KEY] " + context + " has keywords!");
                StringBuilder readable = new StringBuilder();
                for (int i = 0; i < data.length; i++) {
                    int b = data[i] & 0xFF;
                    if (b >= 32 && b < 127) {
                        readable.append((char) b);
                    } else {
                        readable.append('.');
                    }
                }
                XposedBridge.log(TAG + ": [PROTO-ASCII] " + context + ": " + readable.toString());
            }
        } catch (Throwable ignored) {}
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
