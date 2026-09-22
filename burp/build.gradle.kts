// SPDX-License-Identifier: MIT
// wsprobe Burp companion — build file. Part of the wsprobe toolkit, MIT licensed.

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "1.9.24"
    // Bundles the one runtime dependency (SnakeYAML) into the extension JAR,
    // since Burp provides only the Montoya API on the extension classpath.
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "wsprobe"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // Montoya API is provided by Burp at runtime, so compile against it only.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2023.12.1")
    // SnakeYAML (Apache-2.0) parses observed JSON frames (YAML is a JSON
    // superset). It is bundled into the JAR by the shadow plugin.
    implementation("org.yaml:snakeyaml:2.2")

    testImplementation(kotlin("test"))
    testImplementation("net.portswigger.burp.extensions:montoya-api:2023.12.1")
}

kotlin {
    // Target JDK 17 bytecode so the JAR loads in Burp's JRE (17+). Compiles
    // with whatever JDK runs Gradle (17 or newer); no separate JDK 17 install
    // is required.
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    // The loadable artifact. Add to Burp via Extensions > Add > Java.
    archiveBaseName.set("wsprobe-burp")
    archiveClassifier.set("")
    archiveVersion.set(version.toString())
}

// `gradle build` produces the shadow (fat) JAR as the deliverable.
tasks.build {
    dependsOn(tasks.shadowJar)
}
