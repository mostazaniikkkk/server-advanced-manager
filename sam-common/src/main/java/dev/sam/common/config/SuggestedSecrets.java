package dev.sam.common.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * RF-CFG-08 (H-10 de HARDENING.md): los valores sugeridos para los secretos maestros se escriben en un
 * archivo solo del dueño, nunca en el log. La consola solo dice dónde está.
 */
public final class SuggestedSecrets {

    private static final Pattern NAME = Pattern.compile("[A-Z][A-Z0-9_]*");
    private static final Pattern VALUE = Pattern.compile("[\\x21-\\x7e]+");
    private static final String HEADER = """
        # Valores sugeridos por SAM para sus secretos maestros (RF-CFG-08).
        # Defínelos como variable de entorno del proceso del servidor (nunca en el .env), guárdalos en un lugar
        # seguro y después borra este archivo.
        """;

    private SuggestedSecrets() {
    }

    public static void save(Path file, String name, String value) throws IOException {
        if (!NAME.matcher(name).matches() || !VALUE.matcher(value).matches()) {
            throw new IllegalArgumentException("nombre o valor de secreto inválido");
        }
        Map<String, String> values = new TreeMap<>();
        try {
            for (var line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                var eq = line.indexOf('=');
                if (!line.startsWith("#") && eq > 0) {
                    values.put(line.substring(0, eq), line.substring(eq + 1));
                }
            }
        } catch (NoSuchFileException e) {
            // Primera vez
        }
        values.put(name, value);
        var text = new StringBuilder(HEADER);
        values.forEach((k, v) -> text.append(k).append('=').append(v).append('\n'));
        SecureFiles.writeString(file, text.toString());
    }
}
