plugins {
    `java-library`
}

group = "com.kol"
version = "0.0.1"

subprojects {
    apply(plugin = "java")

    repositories {
        mavenCentral()
    }

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
        modularity.inferModulePath.set(true)
    }
}