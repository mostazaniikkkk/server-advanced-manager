package dev.sam.common.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Funciones de hash usadas por el protocolo. */
public final class Hashes {

    private Hashes() {
    }

    /** SHA-256 de la concatenación de {@code parts}, en orden. */
    public static byte[] sha256(byte[]... parts) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // La especificación de Java SE exige SHA-256 en toda JVM: no puede ocurrir.
            throw new IllegalStateException("La JVM no ofrece SHA-256", e);
        }
        for (var part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }
}
