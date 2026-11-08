plugins {
    alias(libs.plugins.loom)
}

base {
    archivesName = "sam-client"
}

repositories {
    // Cobalt (RS-LUA-01), que trae sam-common: solo ese grupo puede venir de aquí
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
    // Runtime de Lua de los scripts de cliente (RS-LUA-01: la misma sandbox que el servidor)
    implementation(libs.cobalt)
    include(libs.cobalt)
    // QR del 2FA (RF-AUTH-04)
    implementation(libs.qrcodegen)
    include(libs.qrcodegen)
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
// Un segundo cliente a la vez (runClient2) en su propia carpeta: los mods remapeados de run/ quedan
// abiertos por el primero. Lo usa qa-rn04.ps1 (una sesión autenticada reemplaza a la anterior).
loom {
    runs {
        register("client2") {
            client()
            // Obsoleto en Loom 1.19.4, pero sin reemplazo todavía (no hay Property para la carpeta)
            runDir = "run2"
        }
    }
}

listOf("runClient", "runClient2").forEach { runTask -> tasks.named<JavaExec>(runTask) {
    mapOf("samDevPassword" to "sam.dev.password", "samDevEmail" to "sam.dev.email", "samDevQuitAfterJoin" to "sam.dev.quitAfterJoin",
        "samDevFillOnly" to "sam.dev.fillOnly", "samDevConfirm" to "sam.dev.confirm", "samDevCapsLock" to "sam.dev.capsLock", "samDevScreenshot" to "sam.dev.screenshot", "samDevScreenshotDelay" to "sam.dev.screenshotDelay",
        "samDevLeave" to "sam.dev.leave", "samDevServerList" to "sam.dev.serverList", "samDevRepeat" to "sam.dev.repeat", "samDevAccount" to "sam.dev.account", "samDevAccountPassword" to "sam.dev.accountPassword", "samDevTotpFile" to "sam.dev.totpFile", "samDevCommand" to "sam.dev.command",
        "samDevScriptsConsent" to "sam.dev.scriptsConsent", "samDevScriptsScreenshot" to "sam.dev.scriptsScreenshot",
        "samDevWorldScreenshot" to "sam.dev.worldScreenshot",
        "samDevKeepScreen" to "sam.dev.keepScreen",
        "samDevKeysScreen" to "sam.dev.keysScreen",
        "samDevMenu" to "sam.dev.menu",
        "samDevCloseScreenAfter" to "sam.dev.closeScreenAfter")
        .forEach { (property, key) -> (findProperty(property) as String?)?.let { systemProperty(key, it) } }
    (findProperty("samDevServer") as String?)?.let { args("--quickPlayMultiplayer", it) }
    (findProperty("samDevUser") as String?)?.let { args("--username", it) }
} }
