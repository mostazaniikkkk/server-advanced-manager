package dev.sam.common.totp;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * La clave de cifrado de datos (RS-AUTH-03): 32 bytes aleatorios en base64 en {@value #ENV}, una
 * variable de entorno del proceso; nunca en el {@code .env} (RF-CFG-08). No se imprime.
 */
public final class DataKey {

    public static final String ENV = "SAM_DATA_KEY";
    private static final int LENGTH = 32;

    private final SecretKey key;

    private DataKey(byte[] bytes) {
        this.key = new SecretKeySpec(bytes, "AES");
    }

    /** @throws IllegalArgumentException si no son 32 bytes en base64 */
    public static DataKey parse(String value) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(value.strip());
        } catch (IllegalArgumentException e) {
            bytes = new byte[0];
        }
        if (bytes.length != LENGTH) {
            throw new IllegalArgumentException(ENV + " debe ser 32 bytes aleatorios en base64");
        }
        return new DataKey(bytes);
    }

    /** Un valor nuevo para que el operador lo defina (se muestra una vez, no se guarda). */
    public static String suggest(SecureRandom random) {
        var bytes = new byte[LENGTH];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    SecretKey key() {
        return key;
    }

    @Override
    public String toString() {
        return "DataKey[***]";
    }
}
