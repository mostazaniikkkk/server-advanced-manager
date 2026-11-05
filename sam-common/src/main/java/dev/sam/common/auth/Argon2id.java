package dev.sam.common.auth;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Argon2id versión 0x13 (RFC 9106) sobre BouncyCastle. */
public final class Argon2id {

    public static final int MIN_SALT_LENGTH = 8;
    public static final int MIN_OUTPUT_LENGTH = 16;

    private Argon2id() {
    }

    public static byte[] hash(byte[] password, byte[] salt, Argon2Params params, int length) {
        return hash(password, salt, null, null, params, length);
    }

    /**
     * @param secret         clave secreta opcional (RFC 9106 "K"), {@code null} si no se usa
     * @param associatedData datos asociados opcionales (RFC 9106 "X"), {@code null} si no se usan
     */
    public static byte[] hash(byte[] password, byte[] salt, byte[] secret, byte[] associatedData,
            Argon2Params params, int length) {
        if (salt.length < MIN_SALT_LENGTH) {
            throw new IllegalArgumentException("Argon2: el salt debe medir al menos " + MIN_SALT_LENGTH + " bytes");
        }
        if (length < MIN_OUTPUT_LENGTH) {
            throw new IllegalArgumentException("Argon2: la salida debe medir al menos " + MIN_OUTPUT_LENGTH + " bytes");
        }
        // BouncyCastle trata null en secret y additional como "no se usa"
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withSecret(secret)
            .withAdditional(associatedData)
            .withMemoryAsKB(params.memoryKiB())
            .withIterations(params.iterations())
            .withParallelism(params.parallelism())
            .build();
        var generator = new Argon2BytesGenerator();
        generator.init(parameters);
        var output = new byte[length];
        generator.generateBytes(password, output);
        return output;
    }
}
