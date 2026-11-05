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
