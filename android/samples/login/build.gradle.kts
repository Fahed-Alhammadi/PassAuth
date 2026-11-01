// Test app for PassAuth's autofill service and passkey provider (emulator testing only).
// A separate app: never a dependency of :app, never in its bundle, and it has no release build.
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.passauth.samples.login"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.passauth.samples.login"
        minSdk = 34
        targetSdk = 36
        versionCode = 1
        versionName = "1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

androidComponents {
    beforeVariants(selector().withBuildType("release")) { it.enable = false }
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

dependencies {
    implementation(libs.androidx.credentials)
    implementation(libs.kotlinx.coroutines.android)
}
