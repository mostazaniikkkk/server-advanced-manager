plugins {
    alias(libs.plugins.loom) apply false
}

allprojects {
    group = "dev.sam"
    version = "0.3.0"
}

// Detección de cuelgues: una tarea trabada falla sola en lugar de bloquear el build sin aviso.
// Remapear un jar tarda segundos; el resto de las tareas (tests, PIT) tarda pocos minutos.
subprojects {
    // H-21: jars reproducibles (mismo código, mismos bytes): sin fechas de los archivos y en orden fijo
    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
    tasks.configureEach {
        timeout = if (name.contains("remap", ignoreCase = true)) {
            java.time.Duration.ofMinutes(3)
        } else {
            java.time.Duration.ofMinutes(15)
        }
    }
}

// H-21: los jars de release y su SHA256SUMS en build/release (los publica el workflow de release)
val releaseJars = tasks.register<Copy>("releaseJars") {
    dependsOn(":sam-client:build", ":sam-server:build", ":sam-signer:build")
    from(file("sam-client/build/libs/sam-client-${project.version}.jar"))
    from(file("sam-server/build/libs/sam-server-${project.version}.jar"))
    from(file("sam-signer/build/libs/sam-signer-${project.version}.jar"))
    into(layout.buildDirectory.dir("release"))
}
tasks.register("releaseChecksums") {
    dependsOn(releaseJars)
    val dir = layout.buildDirectory.dir("release")
    outputs.file(dir.map { it.file("SHA256SUMS") })
    doLast {
        val folder = dir.get().asFile
        val digest = { f: File -> java.security.MessageDigest.getInstance("SHA-256").digest(f.readBytes())
            .joinToString("") { "%02x".format(it) } }
        val lines = folder.listFiles { f -> f.name.endsWith(".jar") }!!.sortedBy { it.name }
            .joinToString("") { "${digest(it)}  ${it.name}\n" }
        File(folder, "SHA256SUMS").writeText(lines)
        println(lines)
    }
}
