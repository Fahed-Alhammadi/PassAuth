# Keep stack traces readable in Play Console crash reports.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# kotlinx.serialization models (item JSON, stored state).
-keepclassmembers @kotlinx.serialization.Serializable class io.passauth.app.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}

# Room instantiates database implementations reflectively (WorkManager's WorkDatabase_Impl); R8's full
# mode strips their no-arg constructor, which crashed the 0.5.2 release build at launch
# ("NoSuchMethodException: androidx.work.impl.WorkDatabase_Impl.<init> []"). Debug builds don't shrink,
# so test the release APK on the emulator before a release (see CLAUDE.md).
-keep class * extends androidx.room.RoomDatabase { <init>(); }
