plugins {
    kotlin("jvm") version "2.4.10"
    kotlin("plugin.serialization") version "2.4.10"
    id("com.gradleup.shadow") version "9.6.1"
    application
}

group = "com.salyvn.serverdoctor"
version = "0.4.0"

repositories {
    mavenCentral()
}

dependencies {
    // Server configs come from machines that are already misbehaving, so YAML is parsed with
    // SafeConstructor: no tag resolution, no object instantiation, no code from the file runs.
    implementation("org.yaml:snakeyaml:2.6")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("com.github.ajalt.clikt:clikt:5.1.0")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass = "com.salyvn.serverdoctor.MainKt"
    applicationName = "serverdoctor"
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}

// One source of truth for the version: the build stamps it into a resource the CLI reads back, so
// the number in `--version` cannot drift from the number in build.gradle.kts.
tasks.processResources {
    inputs.property("version", project.version.toString())
    filesMatching("serverdoctor-version.properties") {
        expand("version" to project.version.toString())
    }
}

// The thin jar gets a classifier so it cannot overwrite the shaded artifact that users download
// and that the release checksums cover.
tasks.jar {
    archiveClassifier = "thin"
}

tasks.shadowJar {
    archiveClassifier = ""
    archiveBaseName = "serverdoctor"
    manifest {
        attributes["Main-Class"] = "com.salyvn.serverdoctor.MainKt"
        attributes["Implementation-Version"] = project.version.toString()
    }
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
