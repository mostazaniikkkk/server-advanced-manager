package dev.sam.common.identity;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Clave pública Ed25519 del servidor en formato SubjectPublicKeyInfo DER (PROTOCOLO.md 3.1).
 * Se valida al construir: solo se aceptan SPKI Ed25519 canónicas de 44 bytes.
 *
 * <p>La verificación usa el Ed25519 nativo de la JDK (RFC 8032).
 */
public final class ServerPublicKey extends ByteValue {

    public static final int SPKI_LENGTH = 44;
    private static final String ALGORITHM = "Ed25519";

    private final PublicKey publicKey;

    private ServerPublicKey(byte[] spki, PublicKey publicKey) {
        super(spki);
        this.publicKey = publicKey;
    }

    public static ServerPublicKey fromSpki(byte[] spki) {
        var copy = checked(spki, SPKI_LENGTH, "SPKI Ed25519");
        // Con 44 bytes fijos, la JDK solo acepta la codificación canónica (sin parámetros en el
        // AlgorithmIdentifier y sin bits sin usar): ServerPublicKeyTest lo verifica.
        try {
            var key = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(copy));
            return new ServerPublicKey(copy, key);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("La SPKI no es una clave pública Ed25519 válida", e);
        }
    }

    public byte[] spki() {
        return toBytes();
    }

    public Pin pin() {
        return Pin.ofSpki(toBytes());
    }

    /** {@code true} solo si {@code signature} es una firma Ed25519 válida de {@code message}. */
    public boolean verify(byte[] message, byte[] signature) {
        try {
            var verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
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
