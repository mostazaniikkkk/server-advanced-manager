package dev.sam.common.crypto;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/** Verificación Ed25519 con la implementación nativa de la JDK (RFC 8032). */
public final class Ed25519 {

    public static final int PUBLIC_KEY_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 64;
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final String ALGORITHM = "Ed25519";

    private Ed25519() {
    }

    /** SubjectPublicKeyInfo DER (44 bytes) de una clave pública cruda de 32 bytes. */
    public static byte[] spkiFromRaw(byte[] raw) {
        if (raw.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException(
                "La clave pública Ed25519 debe medir " + PUBLIC_KEY_LENGTH + " bytes, no " + raw.length);
        }
        var spki = new byte[SPKI_PREFIX.length + PUBLIC_KEY_LENGTH];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(raw, 0, spki, SPKI_PREFIX.length, PUBLIC_KEY_LENGTH);
        return spki;
    }

    /** @throws IllegalArgumentException si no es una SPKI Ed25519 válida */
    public static PublicKey publicKey(byte[] spki) {
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(spki));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("No es una clave pública Ed25519 válida", e);
        }
    }

    /** {@code true} solo si {@code signature} es una firma Ed25519 válida de {@code message}. */
    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        try {
            var verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (SignatureException e) {
            return false;
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Clave Ed25519 validada que la JDK no acepta", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("La JDK no ofrece Ed25519", e);
        }
    }
}
