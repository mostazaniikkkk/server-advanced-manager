package dev.sam.common.scripts;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import dev.sam.common.crypto.Ed25519PrivateKey;

/** Firma de scripts (lo usa {@code sam-signer}, PROTOCOLO.md 8.2). */
public final class ScriptSigner {

    private static final byte[] DOMAIN = "SAM-script-v1".getBytes(StandardCharsets.US_ASCII);

    private ScriptSigner() {
    }

    /**
     * @param files archivos del script; un {@code signature.json} previo en la raíz se ignora
     * @return el contenido de {@code signature.json}, en forma canónica
     */
    public static byte[] sign(Map<String, byte[]> files, Ed25519PrivateKey key) {
        var lockSha = Lockfile.of(files).sha256();
        var keyId = SigningPublicKey.of(key.publicKeyRaw()).keyId();
        return new ScriptSignature(keyId, lockSha, key.sign(signedMessage(lockSha))).toJson();
    }

    /** {@code "SAM-script-v1" ‖ lock_sha256}: lo que cubre la firma. */
    public static byte[] signedMessage(byte[] lockSha256) {
        return ByteBuffer.allocate(DOMAIN.length + lockSha256.length).put(DOMAIN).put(lockSha256).array();
    }
}
