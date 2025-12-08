plugins {
    java
    application
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

application {
    mainModule.set("com.kol.auth.server")
    mainClass.set("org.cv.auth.server.AuthServerMain")
}

dependencies {
    implementation(project(":auth-core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.1")
}

