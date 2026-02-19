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
        languageVersion = JavaLanguageVersion.of(25)
    }
    withSourcesJar()
}

dependencies {
    api("com.fasterxml.jackson.core:jackson-annotations:2.19.0")
    implementation("de.mkammerer:argon2-jvm-nolibs:2.12")
    implementation("org.postgresql:postgresql:42.7.7")
    implementation("net.java.dev.jna:jna:5.17.0")

    testImplementation(platform("org.junit:junit-bom:5.12.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation("org.mockito:mockito-core:5.18.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.18.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
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
