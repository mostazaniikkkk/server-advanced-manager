package dev.sam.common.auth;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Lo que el servidor guarda de {@code K} (PROTOCOLO.md 6.2): Argon2id con salt propio, en formato PHC
 * {@code $argon2id$v=19$m=…,t=…,p=…$<salt>$<hash>} (base64 sin relleno). El login recalcula con los
 * parámetros guardados y compara en tiempo constante.
 *
 * <p>Los parámetros guardados se acotan: un archivo de cuentas alterado no puede pedir un Argon2 que
 * tumbe el servidor.
 */
public final class PasswordHash {

    public static final int SALT_LENGTH = 16;
    public static final int HASH_LENGTH = 32;

    private static final int MAX_MEMORY_KIB = 1 << 20;
    private static final int MAX_ITERATIONS = 10;
    private static final int MAX_PARALLELISM = 8;
    private static final Pattern PHC = Pattern.compile(
        "\\$argon2id\\$v=19\\$m=([0-9]{1,7}),t=([0-9]{1,2}),p=([0-9])\\$([A-Za-z0-9+/]{22})\\$([A-Za-z0-9+/]{43})");

    private PasswordHash() {
    }

    public static String create(byte[] k, Argon2Params params, SecureRandom random) {
        var salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        var hash = Argon2id.hash(k, salt, params, HASH_LENGTH);
        var b64 = Base64.getEncoder().withoutPadding();
        return "$argon2id$v=19$m=" + params.memoryKiB() + ",t=" + params.iterations() + ",p=" + params.parallelism() + "$"
            + b64.encodeToString(salt) + "$" + b64.encodeToString(hash);
    }

    /**
     * @throws IllegalArgumentException si {@code phc} no es un hash válido de SAM
     */
    public static boolean verify(byte[] k, String phc) {
        var stored = parse(phc);
        return MessageDigest.isEqual(Argon2id.hash(k, stored.salt(), stored.params(), HASH_LENGTH), stored.hash());
    }

    /** Un hash guardado, ya validado. */
    record Stored(Argon2Params params, byte[] salt, byte[] hash) {
    }

    static Stored parse(String phc) {
        var match = PHC.matcher(phc);
        if (!match.matches()) {
            throw invalid();
        }
        var memory = Integer.parseInt(match.group(1));
        var iterations = Integer.parseInt(match.group(2));
        var parallelism = Integer.parseInt(match.group(3));
        if (memory > MAX_MEMORY_KIB || iterations < 1 || iterations > MAX_ITERATIONS || parallelism < 1
                || parallelism > MAX_PARALLELISM) {
            throw invalid();
        }
        var decoder = Base64.getDecoder();
        return new Stored(new Argon2Params(memory, iterations, parallelism), decoder.decode(match.group(4)),
            decoder.decode(match.group(5)));
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("hash de contraseña inválido");
    }
}
