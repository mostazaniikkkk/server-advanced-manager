// sam-signer (RS-SIG-07): firma los scripts en la PC del operador. Las claves privadas nunca van al servidor.
plugins {
    application
    jacoco
    alias(libs.plugins.pitest)
}

repositories {
    mavenCentral()
    // Cobalt, que trae sam-common: solo ese grupo puede venir de aquí
    maven("https://maven.squiddev.cc") {
        name = "SquidDev"
        content { includeGroup("cc.tweaked") }
    }
}

dependencies {
    implementation(project(":sam-common"))
    implementation(libs.bouncycastle.prov)
    // PKCS#8 cifrado con PBES2 (RS-SIG-07)
    implementation(libs.bouncycastle.pkix)
    // El manifest se lee con Gson (en el juego lo provee Minecraft; aquí va incluido)
    implementation(libs.gson)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj)
    testRuntimeOnly(libs.junit.launcher)
}

application {
    mainClass = "dev.sam.signer.SamSigner"
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-classfile", "-Werror"))
}

// Un solo jar ejecutable: java -jar sam-signer.jar
tasks.jar {
    manifest { attributes["Main-Class"] = "dev.sam.signer.SamSigner" }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    val runtimeJars = configurations.runtimeClasspath
    // Declarado como dependencia: el jar de sam-common se construye antes
    dependsOn(runtimeJars)
    from(runtimeJars.map { classpath -> classpath.map { if (it.isDirectory) it else zipTree(it) } }) {
        // Las firmas de los jars originales no valen para el jar combinado
        exclude("META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "META-INF/*.EC", "module-info.class", "META-INF/versions/*/module-info.class")
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    finalizedBy(tasks.jacocoTestReport)
}

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

pitest {
    pitestVersion = libs.versions.pitestCore.get()
    junit5PluginVersion = libs.versions.pitestJunit5.get()
    targetClasses = (findProperty("pitTargets") as String?)?.split(",")?.map { it.trim() } ?: listOf("dev.sam.signer.*")
    targetTests = listOf("dev.sam.signer.*")
    mutators = listOf("STRONGER")
    threads = 4
    outputFormats = listOf("HTML", "XML")
    timestampedReports = false
    mutationThreshold = 100
    // main es solo System.exit y la consola real; borrar secretos de la memoria no se observa desde afuera
    // (Secrets se prueba aparte)
    excludedMethods = listOf("main", "lambda\$main\$*")
    avoidCallsTo = listOf("dev.sam.signer.Secrets")
}
