package dev.sam.common.auth;

/**
 * Parámetros de costo de Argon2id.
 *
 * @param memoryKiB   memoria en KiB (al menos 8 × paralelismo, según la RFC 9106)
 * @param iterations  pasadas sobre la memoria
 * @param parallelism carriles
 */
public record Argon2Params(int memoryKiB, int iterations, int parallelism) {

    /**
     * Derivación en el cliente (PROTOCOLO.md 6.1, P-06). <b>Parte del protocolo</b>: cambiarlos
     * invalida todas las contraseñas existentes y exige una nueva etiqueta ({@code SAM-pw-v2}).
     */
    public static final Argon2Params CLIENT_V1 = new Argon2Params(65536, 3, 1);

    /** Hash en el servidor sobre K (PROTOCOLO.md 6.2): mínimo recomendado por OWASP. */
    public static final Argon2Params SERVER_DEFAULT = new Argon2Params(19456, 2, 1);

    public Argon2Params {
        if (iterations < 1) {
            throw new IllegalArgumentException("Argon2: iterations debe ser >= 1");
        }
        if (parallelism < 1) {
            throw new IllegalArgumentException("Argon2: parallelism debe ser >= 1");
        }
        if (memoryKiB < 8 * parallelism) {
            throw new IllegalArgumentException("Argon2: memoryKiB debe ser >= 8 * parallelism");
        }
    }
}
