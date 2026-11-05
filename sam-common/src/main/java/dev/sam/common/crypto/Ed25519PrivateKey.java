package dev.sam.common.crypto;

import java.util.HexFormat;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Clave privada Ed25519 para firmar (la usa {@code sam-signer} en la máquina del operador;
 * nunca vive en el servidor, RS-SIG-07). Se usa BouncyCastle porque la JDK no permite derivar
 * la clave pública desde la semilla.
 */
public final class Ed25519PrivateKey {

    public static final int SEED_LENGTH = 32;

    private final Ed25519PrivateKeyParameters parameters;
    private final byte[] publicKeyRaw;

    private Ed25519PrivateKey(Ed25519PrivateKeyParameters parameters) {
        this.parameters = parameters;
        this.publicKeyRaw = parameters.generatePublicKey().getEncoded();
    }

    public static Ed25519PrivateKey fromSeed(byte[] seed) {
        if (seed.length != SEED_LENGTH) {
            throw new IllegalArgumentException("La semilla Ed25519 debe medir " + SEED_LENGTH + " bytes, no " + seed.length);
        }
        // Ed25519PrivateKeyParameters copia la semilla
        return new Ed25519PrivateKey(new Ed25519PrivateKeyParameters(seed, 0));
    }

    public byte[] publicKeyRaw() {
        return publicKeyRaw.clone();
    }

    public byte[] sign(byte[] message) {
        var signer = new Ed25519Signer();
        signer.init(true, parameters);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    /** No revela la semilla. */
    @Override
    public String toString() {
        return "Ed25519PrivateKey[pub=" + HexFormat.of().formatHex(publicKeyRaw) + "]";
    }
}
