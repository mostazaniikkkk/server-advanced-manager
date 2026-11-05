package dev.sam.common.identity;

import dev.sam.common.crypto.Hashes;

/**
 * Pin de la identidad de un servidor: SHA-256 de su SubjectPublicKeyInfo en DER
 * (PROTOCOLO.md 3.3, P-04). Se fija la clave y no el certificado, para que reemitir el
 * certificado con la misma clave no dispare alertas.
 */
public final class Pin extends ByteValue {

    public static final int LENGTH = 32;
    private static final String LABEL = "pin";

    private Pin(byte[] bytes) {
        super(bytes);
    }

    public static Pin of(byte[] bytes) {
        return new Pin(checked(bytes, LENGTH, LABEL));
    }

    public static Pin ofSpki(byte[] spkiDer) {
        return new Pin(Hashes.sha256(spkiDer));
    }

    public static Pin fromHex(String hex) {
        return new Pin(parseHex(hex, LENGTH, LABEL));
    }
}
