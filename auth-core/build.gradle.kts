plugins {
    `java-library`
    `maven-publish`
}

version = rootProject.version

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
}

dependencies {
    api("com.fasterxml.jackson.core:jackson-annotations:2.17.1")
    implementation("de.mkammerer:argon2-jvm-nolibs:2.11")
    implementation("org.postgresql:postgresql:42.7.3")
    implementation("net.java.dev.jna:jna:5.14.0")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = "dev.kol"
            artifactId = "auth-core"
            version = project.version.toString()
        }
    }
}
