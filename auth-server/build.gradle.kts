plugins {
    java
    application
    id("org.flywaydb.flyway") version "11.19.0"
}

group = "dev.kol"
version = rootProject.version

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {
    mainClass.set("dev.kol.auth.server.AuthServerMain")
}

dependencies {
    implementation(project(":auth-core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.1")
    implementation("de.mkammerer:argon2-jvm-nolibs:2.11")
    implementation("io.jsonwebtoken:jjwt-api:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.5")
    implementation("org.flywaydb:flyway-core:11.19.0")
    runtimeOnly("org.postgresql:postgresql:42.7.3")
}

flyway {
    url = System.getenv("AUTH_DB_URL") ?: System.getProperty("AUTH_DB_URL") ?: "jdbc:postgresql://localhost:5432/kol_auth"
    user = System.getenv("AUTH_DB_USER") ?: System.getProperty("AUTH_DB_USER") ?: "kol_auth"
    password = System.getenv("AUTH_DB_PASSWORD") ?: System.getProperty("AUTH_DB_PASSWORD") ?: "kol_dev_password"
    locations = arrayOf("filesystem:$projectDir/migrations")
    cleanDisabled = true
}
