package dev.sam.common.scripts;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import dev.sam.common.crypto.Hashes;

/**
 * Lockfile canónico de un script: lo que cubre la firma (PROTOCOLO.md 8.2).
 *
 * <pre>
 * &lt;ruta&gt;\t&lt;sha256 hex en minúsculas&gt;\n   una línea por archivo, ordenadas por ruta
 * </pre>
 *
 * <p>Se excluye el {@code signature.json} de la raíz del script (es la firma misma). Cualquier
 * archivo agregado, quitado o modificado cambia {@link #sha256()}.
 */
public final class Lockfile {

    public static final int MAX_FILES = 256;
    public static final String SIGNATURE_FILE = "signature.json";

    private final List<ScriptPath> paths;
    private final byte[] canonical;
    private final byte[] sha256;

    private Lockfile(List<ScriptPath> paths, byte[] canonical) {
        this.paths = paths;
        this.canonical = canonical;
        this.sha256 = Hashes.sha256(canonical);
    }

    /** @param files ruta → contenido de todos los archivos del script */
    public static Lockfile of(Map<String, byte[]> files) {
        var sorted = new TreeMap<ScriptPath, byte[]>();
        files.forEach((path, content) -> {
            if (!path.equals(SIGNATURE_FILE)) {
                sorted.put(ScriptPath.of(path), content);
            }
        });
        if (sorted.isEmpty()) {
            throw new IllegalArgumentException("Un script debe tener al menos un archivo además de " + SIGNATURE_FILE);
        }
        if (sorted.size() > MAX_FILES) {
            throw new IllegalArgumentException(
                "Un script puede tener como máximo " + MAX_FILES + " archivos, no " + sorted.size());
        }
        var out = new ByteArrayOutputStream();
        sorted.forEach((path, content) -> {
            var line = path.value() + '\t' + HexFormat.of().formatHex(Hashes.sha256(content)) + '\n';
            out.writeBytes(line.getBytes(StandardCharsets.UTF_8));
        });
        return new Lockfile(List.copyOf(sorted.keySet()), out.toByteArray());
    }

    /** Rutas incluidas, en orden canónico. */
    public List<ScriptPath> paths() {
        return paths;
    }

    public byte[] canonicalBytes() {
        return canonical.clone();
    }

    /** SHA-256 de {@link #canonicalBytes()}: el {@code lock_sha256} de {@code signature.json}. */
    public byte[] sha256() {
        return sha256.clone();
    }
}
