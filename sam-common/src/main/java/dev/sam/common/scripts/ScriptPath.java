package dev.sam.common.scripts;

import java.util.regex.Pattern;

/**
 * Ruta de un archivo dentro de un script (PROTOCOLO.md 8.2).
 *
 * <p>Mismas reglas que las resource locations de Minecraft: segmentos de {@code [a-z0-9_.-]}
 * separados por {@code /}, sin {@code .} ni {@code ..} como segmento, sin segmentos vacíos y de
 * hasta 256 caracteres. Al ser solo minúsculas ASCII, no hay colisiones de mayúsculas en Windows
 * ni trucos de Unicode.
 *
 * <p>El orden natural es el de los bytes UTF-8 (que en ASCII coincide con el de los caracteres).
 */
public record ScriptPath(String value) implements Comparable<ScriptPath> {

    public static final int MAX_LENGTH = 256;

    private static final Pattern SEGMENT = Pattern.compile("[a-z0-9_.\\-]+");

    public ScriptPath {
        if (value.isEmpty() || value.length() > MAX_LENGTH) {
            throw invalid(value);
        }
        for (var segment : value.split("/", -1)) {
            if (!SEGMENT.matcher(segment).matches() || segment.equals(".") || segment.equals("..")) {
                throw invalid(value);
            }
        }
    }

    public static ScriptPath of(String value) {
        return new ScriptPath(value);
    }

    @Override
    public int compareTo(ScriptPath other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }

    private static IllegalArgumentException invalid(String value) {
        return new IllegalArgumentException(
            "ruta de script inválida (se admiten [a-z0-9_.-] separados por '/', hasta " + MAX_LENGTH
                + " caracteres): \"" + value + "\"");
    }
}
