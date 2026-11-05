package dev.sam.common.scripts;

import java.util.regex.Pattern;

/** Identificador de una clave de firma: los primeros 8 bytes de su SHA-256, en hex minúscula. */
public record KeyId(String hex) {

    private static final Pattern HEX = Pattern.compile("[0-9a-f]{16}");

    public KeyId {
        if (!HEX.matcher(hex).matches()) {
            throw new IllegalArgumentException("key_id inválido: se esperan 16 dígitos hex en minúsculas, no \"" + hex + "\"");
        }
    }

    public static KeyId of(String hex) {
        return new KeyId(hex);
    }

    @Override
    public String toString() {
        return hex;
    }
}
