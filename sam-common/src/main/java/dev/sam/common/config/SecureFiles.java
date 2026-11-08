package dev.sam.common.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * RF-CFG-10 (H-12 de HARDENING.md): escritura de archivos sensibles, atómica y solo para el dueño desde que
 * el archivo nace. El temporal se restringe antes de escribir el contenido, así que nunca hay un instante en
 * que otro usuario del sistema pueda leerlo.
 */
public final class SecureFiles {

    private SecureFiles() {
    }

    public static void write(Path file, byte[] content) throws IOException {
        var parent = file.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        var tmp = Files.createTempFile(parent, ".sam", ".tmp");
        try {
            FilePermissions.restrictToOwner(tmp);
            Files.write(tmp, content);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    public static void writeString(Path file, String text) throws IOException {
        write(file, text.getBytes(StandardCharsets.UTF_8));
    }
}
