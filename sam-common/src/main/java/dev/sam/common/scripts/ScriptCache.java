package dev.sam.common.scripts;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * La caché de paquetes de script del cliente (RF-LUA-05): un archivo por paquete, con su SHA-256 en hex
 * como nombre. Un archivo que ya no coincide con su nombre se borra al leerlo (RN-31); la firma la vuelve a
 * verificar {@link ClientDelivery} en cada carga.
 */
public final class ScriptCache {

    private static final Pattern HEX = Pattern.compile("[0-9a-f]{64}");

    private final Path dir;

    public ScriptCache(Path dir) {
        this.dir = dir;
    }

    /** El paquete, solo si su contenido todavía da ese hash. */
    public Optional<byte[]> read(String sha256Hex) {
        var file = file(sha256Hex);
        try {
            if (!Files.isRegularFile(file)) {
                return Optional.empty();
            }
            if (Files.size(file) <= ScriptPackage.MAX_PACKAGE) {
                var bytes = Files.readAllBytes(file);
                if (MessageDigest.isEqual(ScriptPackage.sha256(bytes), HexFormat.of().parseHex(sha256Hex))) {
                    return Optional.of(bytes);
                }
            }
            Files.delete(file);
            return Optional.empty();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Guarda el paquete con su hash como nombre (escritura atómica). */
    public void write(byte[] pkg) {
        var file = file(HexFormat.of().formatHex(ScriptPackage.sha256(pkg)));
        try {
            Files.createDirectories(dir);
            var tmp = Files.createTempFile(dir, "pkg", ".tmp");
            Files.write(tmp, pkg);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void delete(String sha256Hex) {
        try {
            Files.deleteIfExists(file(sha256Hex));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Path file(String sha256Hex) {
        if (!HEX.matcher(sha256Hex).matches()) {
            throw new IllegalArgumentException("hash inválido: " + sha256Hex);
        }
        return dir.resolve(sha256Hex);
    }
}
