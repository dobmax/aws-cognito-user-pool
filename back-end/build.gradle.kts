import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version libs.versions.spring.boot apply false
    id("io.spring.dependency-management") version libs.versions.spring.dependency.management
    id("org.jlleitschuh.gradle.ktlint") version libs.versions.gradle.ktlint
    id("io.gitlab.arturbosch.detekt") version libs.versions.gradle.detekt
    kotlin("jvm") version libs.versions.kotlin
    kotlin("plugin.spring") version libs.versions.kotlin
}

group = "org.dobmax.user.pool"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    detektPlugins(libs.detekt.formatting)

    implementation(platform("software.amazon.awssdk:bom:2.23.17"))
    implementation("software.amazon.awssdk:cognitoidentityprovider")

    implementation(libs.spring.boot.starter.web)
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs += "-Xjsr305=strict"
        jvmTarget = "21"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

detekt {
    config = files("./detekt-config.yml")
    buildUponDefaultConfig = true
}
