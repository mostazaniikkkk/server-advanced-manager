package dev.sam.common.auth;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.Function;

import dev.sam.common.crypto.Hashes;
import dev.sam.common.identity.ServerId;

/**
 * Contraseña ligada al servidor (RS-AUTH-01, PROTOCOLO.md 6.1).
 *
 * <pre>
 * salt_c = SHA-256("SAM-pw-v1" ‖ server_id ‖ UTF-8(lower(usuario)))[0..16]
 * K      = Argon2id(UTF-8(NFKC(contraseña)), salt_c, CLIENT_V1, 32 bytes)
 * </pre>
 *
 * <p>El cliente envía K, nunca la contraseña: un servidor falso obtiene un K que solo sirve
 * para su propio server_id.
 */
public final class PasswordDerivation {

    public static final int KEY_LENGTH = 32;
    public static final int SALT_LENGTH = 16;

    private static final byte[] DOMAIN = "SAM-pw-v1".getBytes(StandardCharsets.US_ASCII);

    private PasswordDerivation() {
    }

    public static byte[] clientSalt(ServerId serverId, String username) {
        if (username.isBlank()) {
            throw new IllegalArgumentException("El usuario no puede estar vacío");
        }
        var hash = Hashes.sha256(DOMAIN, serverId.toBytes(),
            username.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(hash, SALT_LENGTH);
    }

    /**
     * Deriva K con los parámetros del protocolo. <b>Borra</b> el arreglo {@code password} al
     * terminar (lo llena de {@code '\0'}), ocurra o no un error.
     */
    public static byte[] deriveClientKey(char[] password, ServerId serverId, String username) {
        return deriveClientKey(password, serverId, username, Argon2Params.CLIENT_V1);
    }

    static byte[] deriveClientKey(char[] password, ServerId serverId, String username, Argon2Params params) {
        return withNfkcUtf8(password, encoded -> {
            var salt = clientSalt(serverId, username);
            return Argon2id.hash(encoded, salt, params, KEY_LENGTH);
        });
    }

    /**
     * Normaliza la contraseña con NFKC, la codifica en UTF-8 y se la pasa a {@code action}.
     * Al terminar, ocurra o no un error, borra tanto {@code password} como los bytes codificados.
     *
     * <p>Limitación de la JVM: {@link Normalizer} devuelve un {@code String} intermedio inmutable
     * que no se puede borrar; queda a merced del recolector de basura.
     */
    static <R> R withNfkcUtf8(char[] password, Function<byte[], R> action) {
        byte[] encoded = new byte[0];
        try {
            if (password.length == 0) {
                throw new IllegalArgumentException("La contraseña no puede estar vacía");
            }
            encoded = Normalizer.normalize(CharBuffer.wrap(password), Normalizer.Form.NFKC)
                .getBytes(StandardCharsets.UTF_8);
            return action.apply(encoded);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(encoded, (byte) 0);
        }
    }
}
