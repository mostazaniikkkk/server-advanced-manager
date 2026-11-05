package dev.sam.common.identity;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * Valor inmutable de longitud fija en bytes, con representación hexadecimal canónica
 * (minúsculas). Copia los bytes al construir y al devolverlos. Dos valores son iguales solo si
 * son del mismo tipo y tienen los mismos bytes.
 */
abstract sealed class ByteValue permits ServerId, Pin, ServerPublicKey {

    private final byte[] bytes;

    /** @param bytes ya validados y copiados por {@link #checked} o {@link #parseHex} */
    ByteValue(byte[] bytes) {
        this.bytes = bytes;
    }

    static byte[] checked(byte[] bytes, int length, String label) {
        if (bytes.length != length) {
            throw new IllegalArgumentException(
                "El " + label + " debe medir " + length + " bytes, no " + bytes.length);
        }
        return bytes.clone();
    }

    static byte[] parseHex(String hex, int length, String label) {
        var message = "El " + label + " en hex es inválido: se esperan " + (length * 2) + " dígitos hexadecimales";
        if (hex.length() != length * 2) {
            throw new IllegalArgumentException(message);
        }
        try {
            return HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(message, e);
        }
    }

    public final byte[] toBytes() {
        return bytes.clone();
    }

    public final String hex() {
        return HexFormat.of().formatHex(bytes);
    }

    @Override
    public final boolean equals(Object other) {
        return other != null && other.getClass() == getClass() && Arrays.equals(bytes, ((ByteValue) other).bytes);
    }

    @Override
    public final int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public final String toString() {
        return getClass().getSimpleName() + "[" + hex() + "]";
    }
}
