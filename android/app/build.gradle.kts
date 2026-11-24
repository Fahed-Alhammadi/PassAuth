plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// The Android app's own version: android/VERSION (see buildSrc/AppVersion.kt).
val appVersion = AppVersion.fromVersionFile(rootProject.file("VERSION").readText())

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

// Sign-in request notifications (FCM): android/app/google-services.json when it exists (gitignored;
// a copy is in Keys/, CI writes it from the GOOGLE_SERVICES_JSON secret). Each variant gets the client
// whose package name is its applicationId as BuildConfig fields (see buildSrc/FirebaseClientConfig.kt);
// without the file they're empty and the app doesn't offer notifications. No google-services plugin.
val googleServices = providers.fileContents(layout.projectDirectory.file("google-services.json")).asText

android {
    namespace = "io.passauth.app"
    // 37.1: Compose 1.13 (BOM 2026.11.01) requires it. Only the compile SDK; targetSdk (the behavior) stays 36.
    compileSdk {
        version = release(37) { minorApiLevel = 1 }
    }

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
    onVariants { v ->
        val firebase = v.applicationId.map { id -> googleServices.orNull?.let { FirebaseClientConfig.parse(it, id) } ?: FirebaseClientConfig("", "", "", "") }
        fun field(name: String, value: (FirebaseClientConfig) -> String) = v.buildConfigFields?.put(
            name,
            firebase.map { com.android.build.api.variant.BuildConfigField("String", FirebaseClientConfig.literal(value(it)), null) },
        )
        field("FIREBASE_APP_ID") { it.appId }
        field("FIREBASE_API_KEY") { it.apiKey }
        field("FIREBASE_PROJECT_ID") { it.projectId }
        field("FIREBASE_SENDER_ID") { it.senderId }
    }
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
    implementation(libs.androidx.work)
    implementation(libs.androidx.browser)
    // Sign-in request notifications only (no analytics): Firebase is set up by hand (PushCenter).
    implementation(libs.firebase.messaging)
    implementation(libs.play.services.base)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)

    // Authenticator QR codes: CameraX for frames, ZXing core to decode them.
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.zxing.core)

    testImplementation(libs.junit)
    // The JVM unit tests call the real Rust core: a host build of crates/core-ffi (see below). JNA's
    // jar carries the desktop jnidispatch libraries, which the Android aar of :core doesn't.
    testImplementation(libs.jna)
}

// The core for the JVM unit tests: scripts/build-android-core.sh builds it for the host too
// (target/debug/libpassauth_ffi.dylib or .so, the build the Kotlin bindings are generated from).
val hostCore = rootProject.file("../target/debug")

tasks.withType<Test>().configureEach {
    // Golden vectors shared with the other clients (GoldenVectorsTest finds the file from the
    // working directory); declared so a change to them re-runs the tests instead of a cache hit.
    inputs.file(rootProject.file("../testdata/vectors.json")).withPropertyName("goldenVectors").withPathSensitivity(PathSensitivity.RELATIVE)
    // The host core the bindings load (JNA); a rebuilt core re-runs the tests too.
    val coreLibs = listOf("libpassauth_ffi.dylib", "libpassauth_ffi.so").map { File(hostCore, it) }
    systemProperty("jna.library.path", hostCore.absolutePath)
    inputs.files(provider { coreLibs.filter { it.isFile } }).withPropertyName("hostCore").withPathSensitivity(PathSensitivity.NONE)
    doFirst {
        check(coreLibs.any { it.isFile }) {
            "The unit tests need the core built for this computer: run scripts/build-android-core.sh from the repository root first."
        }
    }
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
