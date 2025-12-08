plugins {
    java
}

group = "com.kol"
version = rootProject.version

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    modularity.inferModulePath.set(true)
}

dependencies {
    implementation("de.mkammerer:argon2-jvm-nolibs:2.11")
    implementation("org.postgresql:postgresql:42.7.3")
    implementation("net.java.dev.jna:jna:5.14.0")
}
