package dev.sam.common.identity;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Identificador estable de un servidor SAM: 16 bytes aleatorios generados una única vez
 * (PROTOCOLO.md 3.1). No cambia al rotar la clave del certificado.
 *
 * <p>Inmutable: copia los bytes al construir y al devolverlos.
 */
public final class ServerId {

    public static final int LENGTH = 16;

    private static final Pattern HEX = Pattern.compile("[0-9a-fA-F]{" + (LENGTH * 2) + "}");

    private final byte[] bytes;

    private ServerId(byte[] bytes) {
        this.bytes = bytes;
    }

    public static ServerId of(byte[] bytes) {
        if (bytes.length != LENGTH) {
            throw new IllegalArgumentException(
                "El server_id debe medir " + LENGTH + " bytes, no " + bytes.length);
        }
        return new ServerId(bytes.clone());
    }

    public static ServerId fromHex(String hex) {
        if (!HEX.matcher(hex).matches()) {
            throw new IllegalArgumentException("server_id en hex inválido: se esperan 32 dígitos hexadecimales");
        }
        return new ServerId(HexFormat.of().parseHex(hex));
    }

    public byte[] toBytes() {
        return bytes.clone();
    }

    /** Representación canónica: 32 dígitos hexadecimales en minúsculas. */
    public String hex() {
        return HexFormat.of().formatHex(bytes);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ServerId that && Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return "ServerId[" + hex() + "]";
    }
}
