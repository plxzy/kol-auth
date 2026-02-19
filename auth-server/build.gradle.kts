plugins {
    java
    application
    id("org.flywaydb.flyway") version "12.0.1"
}

group = "dev.kol"
version = rootProject.version

buildscript {
    dependencies {
        classpath("org.flywaydb:flyway-database-postgresql:12.0.1")
    }
}

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

application {
    mainClass.set("dev.kol.auth.server.AuthServerMain")
}

dependencies {
    implementation(project(":auth-core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.0")
    implementation("de.mkammerer:argon2-jvm:2.12")
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")
    implementation("org.flywaydb:flyway-core:12.0.1")
    runtimeOnly("org.flywaydb:flyway-database-postgresql:12.0.1")
    runtimeOnly("org.postgresql:postgresql:42.7.7")

    testImplementation(platform("org.junit:junit-bom:5.12.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation("org.mockito:mockito-core:5.18.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.18.0")
    testImplementation("io.rest-assured:rest-assured:5.5.6")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

flyway {
    url = System.getenv("AUTH_DB_URL") ?: System.getProperty("AUTH_DB_URL") ?: "jdbc:postgresql://localhost:5432/kol_auth"
    user = System.getenv("AUTH_DB_USER") ?: System.getProperty("AUTH_DB_USER") ?: "kol_auth"
    password = System.getenv("AUTH_DB_PASSWORD") ?: System.getProperty("AUTH_DB_PASSWORD") ?: "kol_dev_password"
    locations = arrayOf("filesystem:$projectDir/migrations")
    cleanDisabled = true
}
