package dev.sam.common.proto.scripts;

/** Los SHA-256 de paquetes de script que viajan en 5.5: siempre 32 bytes, copiados. */
final class Hashes {

    static final int LENGTH = 32;

    private Hashes() {
    }

    static byte[] check(byte[] sha256) {
        if (sha256.length != LENGTH) {
            throw new IllegalArgumentException("sha256 debe tener 32 bytes");
        }
        return sha256.clone();
    }
}
