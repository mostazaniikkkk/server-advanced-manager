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

    /** Lo que escribe el contenido en el temporal (para archivos grandes, sin tenerlos enteros en memoria). */
    public interface Content {
        void writeTo(java.io.OutputStream out) throws IOException;
    }

    public static void write(Path file, byte[] content) throws IOException {
        write(file, out -> out.write(content), true);
    }

    /**
     * @param replace si puede reemplazar un archivo existente; si no, falla con
     *     {@link java.nio.file.FileAlreadyExistsException}
     */
    public static void write(Path file, Content content, boolean replace) throws IOException {
        // En Windows, ATOMIC_MOVE reemplaza aunque no se pida: se comprueba antes
        if (!replace && Files.exists(file)) {
            throw new java.nio.file.FileAlreadyExistsException(file.toString());
        }
        var parent = file.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        var tmp = Files.createTempFile(parent, ".sam", ".tmp");
        try {
            FilePermissions.restrictToOwner(tmp);
            try (var out = Files.newOutputStream(tmp)) {
                content.writeTo(out);
            }
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    public static void writeString(Path file, String text) throws IOException {
        write(file, text.getBytes(StandardCharsets.UTF_8));
    }
}
