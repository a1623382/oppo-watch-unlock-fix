package com.opporootfix.hook;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class OppoWatchUnlockFix implements IXposedHookLoadPackage {

    private static final String TAG = "OPPOWatchFix";

    private static final Set<String> TARGET_PACKAGES = new HashSet<>();

    static {
        TARGET_PACKAGES.add("com.oplus.linker");
        TARGET_PACKAGES.add("com.heytap.htms");
        TARGET_PACKAGES.add("com.heytap.htms:sysintegrity");
        TARGET_PACKAGES.add("com.heytap.health");
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        String pkgName = lpparam.packageName;

        if (!TARGET_PACKAGES.contains(pkgName)) {
            return;
        }

        XposedBridge.log(TAG + ": Hooking package: " + pkgName);

        if ("com.oplus.linker".equals(pkgName)) {
            hookLinkerApp(lpparam);
        }

        if ("com.heytap.htms".equals(pkgName) || "com.heytap.htms:sysintegrity".equals(pkgName)) {
            hookSysIntegrity(lpparam);
        }

        if ("com.heytap.health".equals(pkgName)) {
            hookHealthApp(lpparam);
        }
    }

    private void hookLinkerApp(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": Hooking com.oplus.linker");

        hookEncryptionUtils(lpparam);
        hookConnectionSocket(lpparam);
        hookAttestationCheck(lpparam);
    }

    private void hookEncryptionUtils(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> encryptionUtilsClass = findClass("com.oplus.linker.unlock.utils.EncryptionUtils", lpparam.classLoader);
            if (encryptionUtilsClass == null) {
                encryptionUtilsClass = findClass("com.oplus.linker.crypto.EncryptionUtils", lpparam.classLoader);
            }
            if (encryptionUtilsClass == null) {
                encryptionUtilsClass = findClass("com.oplus.linker.EncryptionUtils", lpparam.classLoader);
            }

            if (encryptionUtilsClass != null) {
                for (Method method : encryptionUtilsClass.getDeclaredMethods()) {
                    if (method.getName().equals("decrypt") || method.getName().contains("decrypt")) {
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Throwable throwable = param.getThrowable();
                                if (throwable != null) {
                                    String errorStr = throwable.toString();
                                    if (errorStr.contains("BadPadding") || errorStr.contains("BAD_DECRYPT") ||
                                        errorStr.contains("decryption") || errorStr.contains("decrypt")) {
                                        XposedBridge.log(TAG + ": Intercepted decrypt error: " + errorStr);
                                        param.setThrowable(null);
                                        param.setResult(null);
                                    }
                                }
                            }
                        });
                        XposedBridge.log(TAG + ": Hooked decrypt method: " + method.getName());
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook EncryptionUtils directly: " + t.getMessage());
        }

        hookCipherDecrypt(lpparam);
    }

    private void hookCipherDecrypt(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> cipherClass = javax.crypto.Cipher.class;

            XposedBridge.hookMethod(
                cipherClass.getMethod("doFinal", byte[].class),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Throwable throwable = param.getThrowable();
                        if (throwable != null) {
                            String errorStr = throwable.toString();
                            if (errorStr.contains("BadPadding") || errorStr.contains("IllegalBlockSize")) {
                                XposedBridge.log(TAG + ": Intercepted Cipher.doFinal error: " + errorStr);
                                param.setThrowable(null);
                                param.setResult(new byte[0]);
                            }
                        }
                    }
                }
            );

            XposedBridge.hookMethod(
                cipherClass.getMethod("doFinal"),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Throwable throwable = param.getThrowable();
                        if (throwable != null) {
                            String errorStr = throwable.toString();
                            if (errorStr.contains("BadPadding") || errorStr.contains("IllegalBlockSize")) {
                                XposedBridge.log(TAG + ": Intercepted Cipher.doFinal() error: " + errorStr);
                                param.setThrowable(null);
                                param.setResult(new byte[0]);
                            }
                        }
                    }
                }
            );

            XposedBridge.log(TAG + ": Hooked javax.crypto.Cipher");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook Cipher: " + t.getMessage());
        }
    }

    private void hookConnectionSocket(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String[] classNames = {
                "com.oplus.linker.unlock.ConnectionSocket",
                "com.oplus.linker.ConnectionSocket",
                "com.oplus.linker.socket.ConnectionSocket",
                "com.oplus.linker.unlock.socket.ConnectionSocket"
            };

            for (String className : classNames) {
                Class<?> clazz = findClass(className, lpparam.classLoader);
                if (clazz != null) {
                    for (Method method : clazz.getDeclaredMethods()) {
                        String methodName = method.getName();
                        if (methodName.contains("LockEvent") || methodName.contains("lockEvent") ||
                            methodName.contains("processLock")) {
                            XposedBridge.hookMethod(method, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                    XposedBridge.log(TAG + ": Hooked " + methodName + " called");
                                    Throwable throwable = param.getThrowable();
                                    if (throwable != null) {
                                        XposedBridge.log(TAG + ": Cleared error in " + methodName);
                                        param.setThrowable(null);
                                    }
                                }
                            });
                            XposedBridge.log(TAG + ": Hooked " + className + "." + methodName);
                        }
                    }
                    break;
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook ConnectionSocket: " + t.getMessage());
        }
    }

    private void hookAttestationCheck(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String[] srpClasses = {
                "com.oplus.omes.srp.SrpProviderModule",
                "com.oplus.omes.srp.SrpManager",
                "com.oplus.omes.srp.AttestationUtils",
                "com.oplus.linker.unlock.srp.SrpUtils"
            };

            for (String className : srpClasses) {
                Class<?> clazz = findClass(className, lpparam.classLoader);
                if (clazz != null) {
                    for (Method method : clazz.getDeclaredMethods()) {
                        String methodName = method.getName().toLowerCase();
                        if (methodName.contains("integrity") || methodName.contains("attest") ||
                            methodName.contains("verify") || methodName.contains("check")) {
                            XposedBridge.hookMethod(method, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                    XposedBridge.log(TAG + ": Bypassing check in " + method.getName());
                                }

                                @Override
                                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                    Object result = param.getResult();
                                    if (result instanceof Boolean) {
                                        param.setResult(true);
                                        XposedBridge.log(TAG + ": Forced " + method.getName() + " to return true");
                                    } else if (result instanceof Integer) {
                                        param.setResult(0);
                                        XposedBridge.log(TAG + ": Forced " + method.getName() + " to return 0");
                                    }
                                }
                            });
                            XposedBridge.log(TAG + ": Hooked " + className + "." + method.getName());
                        }
                    }
                }
            }

            hookSysIntegrityProvider(lpparam);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook attestation check: " + t.getMessage());
        }
    }

    private void hookSysIntegrityProvider(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String[] providerClasses = {
                "com.oplus.omes.srp.provider.IntegrityProvider",
                "com.oplus.omes.srp.provider.DeviceIntegrityProvider",
                "com.oplus.linker.integrity.IntegrityChecker"
            };

            for (String className : providerClasses) {
                Class<?> clazz = findClass(className, lpparam.classLoader);
                if (clazz != null) {
                    for (Method method : clazz.getDeclaredMethods()) {
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object result = param.getResult();
                                if (result instanceof Boolean) {
                                    param.setResult(true);
                                    XposedBridge.log(TAG + ": Forced integrity result to true in " + method.getName());
                                }
                            }
                        });
                        XposedBridge.log(TAG + ": Hooked integrity provider: " + className + "." + method.getName());
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook integrity provider: " + t.getMessage());
        }
    }

    private void hookSysIntegrity(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": Hooking sysintegrity process");

        hookMSPIntegrity(lpparam);
        hookStdSrp(lpparam);
    }

    private void hookMSPIntegrity(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String[] mspClasses = {
                "com.oplus.omes.msp.MspProviderModule",
                "com.oplus.omes.srp.SrpProviderModule",
                "com.oplus.msp.core.IntegrityChecker",
                "com.heytap.htms.integrity.IntegrityService"
            };

            for (String className : mspClasses) {
                Class<?> clazz = findClass(className, lpparam.classLoader);
                if (clazz != null) {
                    for (Method method : clazz.getDeclaredMethods()) {
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object result = param.getResult();
                                if (result instanceof Boolean) {
                                    param.setResult(true);
                                    XposedBridge.log(TAG + ": Forced MSP integrity to true");
                                } else if (result instanceof Integer) {
                                    if ((Integer) result != 0) {
                                        param.setResult(0);
                                        XposedBridge.log(TAG + ": Forced MSP integrity code to 0");
                                    }
                                }
                            }
                        });
                        XposedBridge.log(TAG + ": Hooked MSP: " + className + "." + method.getName());
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook MSP integrity: " + t.getMessage());
        }
    }

    private void hookStdSrp(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            String[] srpClasses = {
                "com.oplus.omes.srp.StdSrp",
                "com.oplus.omes.srp.SrpClient",
                "com.oplus.omes.srp.CryptoUtils"
            };

            for (String className : srpClasses) {
                Class<?> clazz = findClass(className, lpparam.classLoader);
                if (clazz != null) {
                    for (Method method : clazz.getDeclaredMethods()) {
                        String name = method.getName().toLowerCase();
                        if (name.contains("attest") || name.contains("integrity") || name.contains("verify")) {
                            XposedBridge.hookMethod(method, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                    Object result = param.getResult();
                                    if (result instanceof Boolean) {
                                        param.setResult(true);
                                        XposedBridge.log(TAG + ": Forced SRP result to true");
                                    }
                                }
                            });
                            XposedBridge.log(TAG + ": Hooked SRP: " + className + "." + method.getName());
                        }
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook SRP: " + t.getMessage());
        }
    }

    private void hookHealthApp(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + ": Hooking com.heytap.health");

        try {
            String[] classNames = {
                "com.heytap.health.unlock.WatchUnlockManager",
                "com.heytap.health.watch.unlock.WatchUnlockHelper",
                "com.heytap.health.smartlock.SmartLockManager"
            };

            for (String className : classNames) {
                Class<?> clazz = findClass(className, lpparam.classLoader);
                if (clazz != null) {
                    for (Method method : clazz.getDeclaredMethods()) {
                        String name = method.getName().toLowerCase();
                        if (name.contains("unlock") || name.contains("smartlock") || name.contains("trust")) {
                            XposedBridge.hookMethod(method, new XC_MethodHook() {
                                @Override
                                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                    Object result = param.getResult();
                                    if (result instanceof Boolean) {
                                        param.setResult(true);
                                        XposedBridge.log(TAG + ": Forced health unlock to true");
                                    }
                                }
                            });
                            XposedBridge.log(TAG + ": Hooked health: " + className + "." + method.getName());
                        }
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook health app: " + t.getMessage());
        }
    }

    private Class<?> findClass(String className, ClassLoader classLoader) {
        try {
            return XposedHelpers.findClass(className, classLoader);
        } catch (Throwable t) {
            return null;
        }
    }
}
