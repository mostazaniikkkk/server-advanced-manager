plugins {
    alias(libs.plugins.loom)
}

base {
    archivesName = "sam-client"
}

dependencies {
    minecraft(libs.minecraft)
    mappings(loom.officialMojangMappings())
    modImplementation(libs.fabric.loader)
    modImplementation(libs.fabric.api)

    // Embebidos (jar-in-jar): el jugador instala un solo jar
    implementation(project(":sam-common"))
    include(project(":sam-common"))
    implementation(libs.bouncycastle.prov)
    include(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.pkix)
    include(libs.bouncycastle.pkix)
    include(libs.bouncycastle.util)
    implementation(libs.netty.codec.http)
    include(libs.netty.codec.http)
}

// Gradle corre sobre JDK 25 (Loom 1.19 lo exige); se compila para Java 21
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
}

tasks.processResources {
    val version = project.version.toString()
    inputs.property("version", version)
    filesMatching("fabric.mod.json") {
        expand("version" to version)
    }
}

// ===== Prueba de punta a punta en el entorno de desarrollo (solo a pedido) =====
// gradlew :sam-client:runClient -PsamDevServer=127.0.0.1:25567 -PsamDevPassword=... -PsamDevQuitAfterJoin=8
tasks.named<JavaExec>("runClient") {
    mapOf("samDevPassword" to "sam.dev.password", "samDevEmail" to "sam.dev.email", "samDevQuitAfterJoin" to "sam.dev.quitAfterJoin",
        "samDevFillOnly" to "sam.dev.fillOnly", "samDevScreenshot" to "sam.dev.screenshot", "samDevScreenshotDelay" to "sam.dev.screenshotDelay")
        .forEach { (property, key) -> (findProperty(property) as String?)?.let { systemProperty(key, it) } }
    (findProperty("samDevServer") as String?)?.let { args("--quickPlayMultiplayer", it) }
    (findProperty("samDevUser") as String?)?.let { args("--username", it) }
}
