pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "PassAuth"
include(":core", ":app")
// Debug-only test app for the autofill service (never part of the PassAuth app or its release bundle).
include(":samples:login")
