# Consumer ProGuard rules for tauri-plugin-biometry.
#
# Generic @TauriPlugin / @Command / @InvokeArg keep rules are provided by
# the tauri-api consumer rules — only plugin-specific rules go here.

# BiometryResultType is serialized as a string into the result Intent by
# BiometryActivity and recovered with valueOf() in BiometryPlugin's
# authenticateResult callback. R8 keeps used enums, but be explicit so
# the name-based lookup cannot be obfuscated.
-keepclassmembers enum app.tauri.biometry.BiometryResultType {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# BiometryActivity is referenced from AndroidManifest.xml (R8 normally
# preserves manifest-referenced classes, but keeping it explicitly avoids
# any manifest-merge surprises in consumer builds).
-keep class app.tauri.biometry.BiometryActivity { *; }
