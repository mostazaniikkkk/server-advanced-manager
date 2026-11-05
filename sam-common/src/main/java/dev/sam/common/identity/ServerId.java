package dev.sam.common.identity;

/**
 * Identificador estable de un servidor SAM: 16 bytes aleatorios generados una única vez
 * (PROTOCOLO.md 3.1). No cambia al rotar la clave del certificado.
 */
public final class ServerId extends ByteValue {

    public static final int LENGTH = 16;
    private static final String LABEL = "server_id";

    private ServerId(byte[] bytes) {
        super(bytes);
    }

    public static ServerId of(byte[] bytes) {
        return new ServerId(checked(bytes, LENGTH, LABEL));
    }

    public static ServerId fromHex(String hex) {
        return new ServerId(parseHex(hex, LENGTH, LABEL));
    }
}
