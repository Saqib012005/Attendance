import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing material. key.properties and the keystore itself are both
// gitignored (see ../../.gitignore and android/.gitignore); nothing here is
// committed. Absent the file there is no release signing config at all, which
// is what makes the failure below possible.
val keystoreProperties = Properties()
val keystorePropertiesFile = rootProject.file("key.properties")
if (keystorePropertiesFile.exists()) {
    FileInputStream(keystorePropertiesFile).use { keystoreProperties.load(it) }
}

android {
    namespace = "com.example.attendance_app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    defaultConfig {
        // Off the com.example.* default namespace: Play rejects it outright, and it
        // is not an identity anyone controls. `namespace` above is deliberately
        // left alone so MainActivity.kt does not have to move.
        // Reverse-DNS convention wants a domain you own - change this one line if
        // CampusGuard ships under a different one.
        applicationId = "com.campusguard.attendance"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        // Declared only when key.properties is present. A half-populated config
        // would be worse than none: it would let a release build fall back to
        // some other key without saying so.
        if (keystorePropertiesFile.exists()) {
            create("release") {
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
                storeFile = keystoreProperties.getProperty("storeFile")?.let { file(it) }
                storePassword = keystoreProperties.getProperty("storePassword")
            }
        }
    }

    buildTypes {
        release {
            // Was signingConfigs.getByName("debug"), so every release APK was
            // signed with the machine-local debug key - a key whose private half
            // ships with every Android SDK install and whose fingerprint differs
            // per machine. App Links verification and any future key-pinned
            // presence claim both need the signing identity to be stable and
            // secret. Null here rather than a fallback: nothing else may sign a
            // release, and the task-graph check below turns that into a hard stop.
            signingConfig = signingConfigs.findByName("release")
        }
    }
}

// Fail closed, but only for the builds it concerns. Throwing from inside
// buildTypes { release { ... } } above would abort *configuration*, which breaks
// `flutter run` and every debug task as well - so the check waits until Gradle
// knows what it was actually asked to build.
gradle.taskGraph.whenReady {
    val wantsRelease = allTasks.any { it.name.endsWith("Release") }
    if (wantsRelease && !keystorePropertiesFile.exists()) {
        throw GradleException(
            "Refusing to build a release without release signing material: " +
            "android/key.properties is missing. Generate a keystore and write " +
            "key.properties (keyAlias, keyPassword, storeFile, storePassword). " +
            "Debug builds are unaffected. Release builds used to be signed with " +
            "the debug key, which is why this now stops instead of continuing."
        )
    }
}

flutter {
    source = "../.."
}


