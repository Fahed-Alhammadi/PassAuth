# Keep stack traces readable in Play Console crash reports.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# kotlinx.serialization models (item JSON, stored state).
-keepclassmembers @kotlinx.serialization.Serializable class io.passauth.app.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
