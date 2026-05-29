plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.thclab.keri"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        minSdk = 30
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    buildTypes {
        release { isMinifyEnabled = false }
    }

    packaging {
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.fragment:fragment-ktx:1.8.4")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // UniFFI Kotlin runtime
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}

// Build the Rust .so files and run uniffi-bindgen before the Android build.
// Delegates to the top-level Makefile so devs can also drive it directly.
val cargoBuild by tasks.registering(Exec::class) {
    workingDir = file("$projectDir/..")
    commandLine("make", "rust", "bindgen")
    inputs.files(fileTree("../keri-kotlin/src"))
    inputs.file("../keri-kotlin/Cargo.toml")
    outputs.dir("src/main/jniLibs")
    outputs.dir("src/main/java/com/thclab/keri/uniffi")
}

tasks.named("preBuild").configure { dependsOn(cargoBuild) }
