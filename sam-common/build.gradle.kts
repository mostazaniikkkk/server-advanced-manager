plugins {
    `java-library`
    jacoco
    alias(libs.plugins.pitest)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.bouncycastle.prov)
    // Construcción de certificados X.509 (la JDK no tiene API pública para generarlos)
    implementation(libs.bouncycastle.pkix)
    // ID token de Google (RS-OAUTH-05): lo usa el servidor; el cliente nunca carga esas clases
    implementation(libs.nimbus.jose.jwt)
    // Minecraft trae Gson y Netty 4.1.97: se compila contra ellos pero no se empaquetan
    compileOnly(libs.gson)
    testImplementation(libs.gson)
    compileOnly(libs.netty.codec)
    compileOnly(libs.netty.transport)
    compileOnly(libs.netty.buffer)
    compileOnly(libs.netty.handler)
    compileOnly(libs.netty.codec.http)
    testImplementation(libs.netty.codec.http)
    testImplementation(libs.netty.handler)
    testImplementation(libs.netty.codec)
    testImplementation(libs.netty.transport)
    testImplementation(libs.netty.buffer)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj)
    testImplementation(libs.jqwik)
    testImplementation(libs.jimfs)
    testRuntimeOnly(libs.junit.launcher)
}

// Gradle corre sobre JDK 25 (Loom 1.19 lo exige); se compila para Java 21, que es lo que pide Minecraft 1.21.1
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.test {
    useJUnitPlatform {
        includeEngines("junit-jupiter", "jqwik")
    }
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    finalizedBy(tasks.jacocoTestReport)
}

// ===== Cobertura (JaCoCo) =====
jacoco {
    toolVersion = libs.versions.jacoco.get()
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required = true
        html.required = true
    }
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                counter = "BRANCH"
                minimum = "0.90".toBigDecimal()
            }
            limit {
                counter = "LINE"
                minimum = "0.90".toBigDecimal()
            }
        }
    }
}

// ===== Mutation testing (PIT) =====
pitest {
    pitestVersion = libs.versions.pitestCore.get()
    junit5PluginVersion = libs.versions.pitestJunit5.get()
    // -PpitTargets=a.B*,c.D* limita PIT a lo que tocó el ciclo (el 100 % se exige igual)
    targetClasses = (findProperty("pitTargets") as String?)?.split(",")?.map { it.trim() } ?: listOf("dev.sam.*")
    // Siempre todos los tests: si no, el plugin los filtra con el mismo patrón que las clases
    targetTests = listOf("dev.sam.*")
    mutators = listOf("STRONGER")
    threads = 4
    outputFormats = listOf("HTML", "XML")
    timestampedReports = false
    mutationThreshold = 100
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification)
}
