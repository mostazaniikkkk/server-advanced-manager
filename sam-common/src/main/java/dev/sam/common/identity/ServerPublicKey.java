package dev.sam.common.identity;

import java.security.PublicKey;

import dev.sam.common.crypto.Ed25519;

/**
 * Clave pública Ed25519 del servidor en formato SubjectPublicKeyInfo DER (PROTOCOLO.md 3.1).
 * Se valida al construir: solo se aceptan SPKI Ed25519 canónicas de 44 bytes.
 */
public final class ServerPublicKey extends ByteValue {

    public static final int SPKI_LENGTH = 44;

    private final PublicKey publicKey;

    private ServerPublicKey(byte[] spki, PublicKey publicKey) {
        super(spki);
        this.publicKey = publicKey;
    }

    public static ServerPublicKey fromSpki(byte[] spki) {
        var copy = checked(spki, SPKI_LENGTH, "SPKI Ed25519");
        // Con 44 bytes fijos, la JDK solo acepta la codificación canónica (sin parámetros en el
        // AlgorithmIdentifier y sin bits sin usar): ServerPublicKeyTest lo verifica.
        return new ServerPublicKey(copy, Ed25519.publicKey(copy));
    }

    public byte[] spki() {
        return toBytes();
    }

    public Pin pin() {
        return Pin.ofSpki(toBytes());
    }

    /** {@code true} solo si {@code signature} es una firma Ed25519 válida de {@code message}. */
    public boolean verify(byte[] message, byte[] signature) {
        return Ed25519.verify(publicKey, message, signature);
    }
}
