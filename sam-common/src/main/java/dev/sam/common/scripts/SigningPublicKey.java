package dev.sam.common.scripts;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.HexFormat;

import dev.sam.common.crypto.Ed25519;
import dev.sam.common.crypto.Hashes;

/**
 * Clave pública de firma de scripts del operador (PROTOCOLO.md 8.1): 32 bytes crudos, con
 * {@code key_id = SHA-256(clave)[0..8]}.
 */
public final class SigningPublicKey {

    private final byte[] raw;
    private final PublicKey publicKey;
    private final KeyId keyId;

    private SigningPublicKey(byte[] raw) {
        this.raw = raw;
        this.publicKey = Ed25519.publicKey(Ed25519.spkiFromRaw(raw));
        this.keyId = KeyId.of(HexFormat.of().formatHex(Hashes.sha256(raw), 0, 8));
    }

    public static SigningPublicKey of(byte[] raw) {
        return new SigningPublicKey(raw.clone());
    }

    public byte[] raw() {
        return raw.clone();
    }

    public KeyId keyId() {
        return keyId;
    }

    public boolean verify(byte[] message, byte[] signature) {
        return Ed25519.verify(publicKey, message, signature);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SigningPublicKey that && Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "SigningPublicKey[" + keyId + "]";
    }
}
