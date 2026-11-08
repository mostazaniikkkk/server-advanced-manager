plugins {
    alias(libs.plugins.loom) apply false
}

allprojects {
    group = "dev.sam"
    version = "0.2.0"
}

// Detección de cuelgues: una tarea trabada falla sola en lugar de bloquear el build sin aviso.
// Remapear un jar tarda segundos; el resto de las tareas (tests, PIT) tarda pocos minutos.
subprojects {
    tasks.configureEach {
        timeout = if (name.contains("remap", ignoreCase = true)) {
            java.time.Duration.ofMinutes(3)
        } else {
            java.time.Duration.ofMinutes(15)
        }
    }
}
