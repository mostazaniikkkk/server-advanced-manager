package dev.sam.common.net;

/**
 * Clasifica una conexión entrante por sus primeros bytes (RS-NET-06, PROTOCOLO.md 2.1).
 *
 * <p>Es una función pura: no consume ni modifica la entrada. Garantías:
 * <ul>
 *   <li>Con 4 bytes o más siempre devuelve una clasificación definitiva.</li>
 *   <li>Una clasificación definitiva no cambia si llegan más bytes.</li>
 * </ul>
 */
public final class ProtocolDetector {

    /** Bytes necesarios, como máximo, para decidir. */
    public static final int MAX_PREFIX = 4;

    private static final byte TLS_HANDSHAKE_RECORD = 0x16;
    private static final byte TLS_MAJOR_VERSION = 0x03;
    private static final byte LEGACY_PING = (byte) 0xFE;
    private static final byte[] HTTP_GET = {'G', 'E', 'T', ' '};

    public enum Classification {
        /** Todavía no hay bytes suficientes para decidir. */
        NEED_MORE,
        /** ClientHello de TLS: va al TLS 1.3 de SAM. */
        TLS,
        /** Petición HTTP {@code GET}: candidato a WebSocket. */
        HTTP,
        /** Ping de la lista de servidores anterior a 1.7. */
        LEGACY_PING,
        /** Cualquier otra cosa: handshake vanilla en claro (camino restringido). */
        VANILLA
    }

    private ProtocolDetector() {
    }

    public static Classification classify(byte[] prefix) {
        if (prefix.length == 0) {
            return Classification.NEED_MORE;
        }
        byte first = prefix[0];
        if (first == LEGACY_PING) {
            return Classification.LEGACY_PING;
        }
        if (first == TLS_HANDSHAKE_RECORD) {
            if (prefix.length < 2) {
                return Classification.NEED_MORE;
            }
            return prefix[1] == TLS_MAJOR_VERSION ? Classification.TLS : Classification.VANILLA;
        }
        if (first == HTTP_GET[0]) {
            return classifyGet(prefix);
        }
        return Classification.VANILLA;
    }

    private static Classification classifyGet(byte[] prefix) {
        int comparable = Math.min(prefix.length, HTTP_GET.length);
        for (int i = 1; i < comparable; i++) {
            if (prefix[i] != HTTP_GET[i]) {
                return Classification.VANILLA;
            }
        }
        return prefix.length >= HTTP_GET.length ? Classification.HTTP : Classification.NEED_MORE;
    }
}
