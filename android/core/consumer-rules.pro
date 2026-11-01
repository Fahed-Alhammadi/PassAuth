# UniFFI bindings call into Rust through JNA, which uses reflection.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class io.passauth.core.** { *; }
-dontwarn java.awt.**
