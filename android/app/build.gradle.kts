plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Same version as the server: root Cargo.toml [workspace.package] version (see buildSrc/AppVersion.kt).
val appVersion = AppVersion.fromCargoToml(rootProject.file("../Cargo.toml").readText())

// Release signing only when CI (or you) provide the upload key; local builds never need it.
val uploadKeystore = providers.environmentVariable("ANDROID_UPLOAD_KEYSTORE_PATH").orNull
val uploadSigning = uploadKeystore?.takeIf { it.isNotBlank() }?.let {
    listOf(
        "ANDROID_UPLOAD_KEYSTORE_PASSWORD",
        "ANDROID_UPLOAD_KEY_ALIAS",
        "ANDROID_UPLOAD_KEY_PASSWORD",
    ).map { name ->
        providers.environmentVariable(name).orNull?.takeIf { v -> v.isNotEmpty() }
            ?: error("ANDROID_UPLOAD_KEYSTORE_PATH is set but $name is missing")
    }
}

// Screenshots of secret screens are blocked (FLAG_SECURE). For local UI testing only:
// ./gradlew :app:assembleDebug -Ppassauth.allowScreenshots=true (never applies to release).
val allowScreenshots = providers.gradleProperty("passauth.allowScreenshots").orNull == "true"

// Debug builds only: fetch Digital Asset Links from a local test server instead of
// https://<domain>/.well-known/assetlinks.json, e.g. -Ppassauth.testAssetLinksBase=http://10.0.2.2:8094
// (emulator tests of passkeys for apps). Never applies to release builds.
val testAssetLinksBase = providers.gradleProperty("passauth.testAssetLinksBase").orNull.orEmpty()

// Debug builds only: trust one more browser as privileged ("package|SHA-256 cert fingerprint"),
// e.g. a Chromium snapshot build on the emulator. Never applies to release builds.
val testPrivilegedApp = providers.gradleProperty("passauth.testPrivilegedApp").orNull.orEmpty()

android {
    namespace = "io.passauth.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.passauth.app"
        minSdk = 34
        targetSdk = 36
        versionName = appVersion.name
        versionCode = appVersion.code
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
        buildConfigField("String", "ASSET_LINKS_TEST_BASE", "\"\"")
        buildConfigField("String", "TEST_PRIVILEGED_APP", "\"\"")
    }

    signingConfigs {
        if (uploadSigning != null) {
            create("upload") {
                storeFile = file(uploadKeystore!!)
                storePassword = uploadSigning[0]
                keyAlias = uploadSigning[1]
                keyPassword = uploadSigning[2]
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", allowScreenshots.toString())
            buildConfigField("String", "ASSET_LINKS_TEST_BASE", "\"$testAssetLinksBase\"")
            buildConfigField("String", "TEST_PRIVILEGED_APP", "\"$testPrivilegedApp\"")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = if (uploadSigning != null) signingConfigs.getByName("upload") else null
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += listOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/versions/9/OSGI-INF/MANIFEST.MF")
    }

    sourceSets {
        // The version logic is unit-tested together with the app.
        getByName("test").kotlin.srcDir(rootProject.file("buildSrc/src/main/kotlin"))
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

// AGP 9 creates host (unit) tests for the debug build type only; the release workflow runs
// :app:testReleaseUnitTest, so enable them for every build type.
androidComponents {
    beforeVariants { v -> v.hostTests[com.android.build.api.variant.HostTestBuilder.UNIT_TEST_TYPE]?.enable = true }
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

dependencies {
    implementation(project(":core"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.datastore)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.autofill)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)

    // Authenticator QR codes: CameraX for frames, ZXing core to decode them.
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.zxing.core)

    testImplementation(libs.junit)
}

tasks.withType<Test>().configureEach {
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    afterSuite(KotlinClosure2<TestDescriptor, TestResult, Unit>({ desc, result ->
        if (desc.parent == null) {
            println("Unit tests: ${result.testCount} run, ${result.failedTestCount} failed, ${result.skippedTestCount} skipped")
        }
    }))
}
