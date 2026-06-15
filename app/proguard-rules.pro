# Keep Xposed entry point
-keep class com.opporootfix.hook.RootBypassHook {
    *;
}

# Keep Xposed API
-keep class de.robv.android.xposed.** { *; }
-keepclassmembers class * {
    @de.robv.android.xposed.* <methods>;
}
