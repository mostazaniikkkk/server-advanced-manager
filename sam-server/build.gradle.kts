import java.util.Properties

plugins {
    alias(libs.plugins.loom)
}

base {
    archivesName = "sam-server"
}

repositories {
    // Cobalt (RS-LUA-01): solo ese grupo puede venir de aquí
    maven("https://maven.squiddev.cc") {
        name = "SquidDev"
        content { includeGroup("cc.tweaked") }
    }
}

dependencies {
    minecraft(libs.minecraft)
    mappings(loom.officialMojangMappings())
    modImplementation(libs.fabric.loader)
    modImplementation(libs.fabric.api)

    // Embebidos (jar-in-jar): el operador instala un solo jar
    implementation(project(":sam-common"))
    include(project(":sam-common"))
    implementation(libs.bouncycastle.prov)
    include(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.pkix)
    include(libs.bouncycastle.pkix)
    include(libs.bouncycastle.util)
    // Lua de los scripts (RS-LUA-01); la misma versión que soulsmode: Fabric deduplica el jar
    implementation(libs.cobalt)
    include(libs.cobalt)
    // ID token de Google (RS-OAUTH-05)
    implementation(libs.nimbus.jose.jwt)
    include(libs.nimbus.jose.jwt)
    implementation(libs.netty.codec.http)
    include(libs.netty.codec.http)
}

// Gradle corre sobre JDK 25 (Loom 1.19 lo exige); se compila para Java 21
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
}

// ===== Pruebas de punta a punta contra el servidor QA en ejecución (solo a pedido) =====
// Un cliente de prueba habla el protocolo de Minecraft por un socket real. No forma parte de `check`.
val qaTestSourceSet = sourceSets.create("qaTest")

dependencies {
    "qaTestImplementation"(project(":sam-common"))
    "qaTestImplementation"(libs.netty.buffer)
    "qaTestImplementation"(libs.netty.codec)
    "qaTestImplementation"(libs.netty.transport)
    "qaTestImplementation"(libs.netty.handler)
    "qaTestImplementation"(libs.netty.codec.http)
    "qaTestImplementation"(platform(libs.junit.bom))
    "qaTestImplementation"(libs.junit.jupiter)
    "qaTestImplementation"(libs.assertj)
    "qaTestRuntimeOnly"(libs.junit.launcher)
}

tasks.register<Test>("qaTest") {
    description = "Pruebas de punta a punta contra el servidor QA en ejecución (127.0.0.1:samQaPort)."
    group = "sam"
    testClassesDirs = qaTestSourceSet.output.classesDirs
    classpath = qaTestSourceSet.runtimeClasspath
    useJUnitPlatform()
    systemProperty("sam.qa.port", (findProperty("samQaPort") as String?) ?: "25567")
    systemProperty("sam.qa.wsPath", (findProperty("samQaWsPath") as String?) ?: "/qa-ws")
    // RN-04: el nick de un jugador real que está en el mundo (lo pone qa-rn04.ps1)
    (findProperty("samQaOnlineNick") as String?)?.let { systemProperty("sam.qa.onlineNick", it) }
    outputs.upToDateWhen { false }
    testLogging {
        events("passed", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// ===== Instalación en el servidor QA local (solo a pedido: nunca la dispara un build) =====
// La ruta es propia de cada máquina: va en local.properties (fuera del repositorio) o con -PsamQaServerDir=...
val localProperties = Properties().apply {
    rootProject.file("local.properties").takeIf { it.exists() }?.reader(Charsets.UTF_8)?.use { load(it) }
}
val qaServerDir: String? = (findProperty("samQaServerDir") as String?) ?: localProperties.getProperty("samQaServerDir")
val qaModsDir = qaServerDir?.let { file("$it/mods") }

val removeOldQaJars = tasks.register<Delete>("removeOldQaJars") {
    description = "Borra versiones anteriores de sam-server de la carpeta mods del servidor QA."
    group = "sam"
    if (qaModsDir != null) {
        delete(fileTree(qaModsDir) { include("sam-server-*.jar") })
    }
}

tasks.register<Copy>("installQaServer") {
    description = "Copia el jar de sam-server a la carpeta mods del servidor QA (samQaServerDir)."
    group = "sam"
    dependsOn(removeOldQaJars)
    from(tasks.named("remapJar"))
    into(qaModsDir ?: layout.buildDirectory.dir("qa-server-no-configurado"))
    doFirst {
        check(qaModsDir != null && qaModsDir.isDirectory) {
            "Configura samQaServerDir en local.properties (o con -PsamQaServerDir=...) apuntando a un servidor con carpeta mods/"
        }
    }
}

tasks.processResources {
    val version = project.version.toString()
    inputs.property("version", version)
    filesMatching("fabric.mod.json") {
        expand("version" to version)
    }
}
