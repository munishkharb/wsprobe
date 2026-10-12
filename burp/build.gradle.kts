// SPDX-License-Identifier: MIT
// wsprobe Burp companion - build file. Part of the wsprobe toolkit, MIT licensed.

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.20"
    // Bundles the one runtime dependency (SnakeYAML) into the extension JAR,
    // since Burp provides only the Montoya API on the extension classpath.
    // com.gradleup.shadow is the maintained fork of the (dead) johnrengelman
    // plugin and is the one that supports Gradle 9.
    id("com.gradleup.shadow") version "9.0.0"
}

group = "wsprobe"
version = "0.2.0"

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
    // with whatever JDK runs Gradle (17 or newer).
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
    // gradleup shadow 9 does not merge the runtime classpath by default, so the
    // Kotlin stdlib and SnakeYAML must be pulled in explicitly or the JAR loads
    // in Burp with ClassNotFoundException: kotlin.jvm.internal.Intrinsics.
    configurations.set(listOf(project.configurations.runtimeClasspath.get()))
    mergeServiceFiles()
}

// `gradle build` produces the shadow (fat) JAR as the deliverable.
tasks.build {
    dependsOn(tasks.shadowJar)
}
