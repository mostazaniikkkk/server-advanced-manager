package dev.sam.common.net;

import dev.sam.common.net.ProtocolDetector.Classification;

/**
 * Decide qué hacer con una conexión entrante según su clasificación, el transporte por el
 * que llegó y la configuración del servidor (PROTOCOLO.md 2.1 y 2.3, RF-WS-03, RS-WS-01).
 *
 * <p>Inmutable: se construye una vez al cargar la configuración.
 */
public final class IngressPolicy {

    public enum Transport {
        /** Socket TCP aceptado directamente por el servidor. */
        DIRECT_TCP,
        /** Flujo de bytes extraído de un WebSocket ya establecido. */
        INSIDE_WEBSOCKET
    }

    public enum Action {
        /** Faltan bytes para decidir: seguir leyendo (con timeout). */
        WAIT,
        /** Insertar el TLS 1.3 de SAM. */
        SAM_TLS,
        /** Hacer el handshake HTTP de WebSocket. */
        WEBSOCKET_HANDSHAKE,
        /** Pipeline vanilla en claro, solo para status y kick (PROTOCOLO.md 2.2). */
        VANILLA_RESTRICTED,
        /** Cerrar la conexión sin respuesta. */
        CLOSE
    }

    private final boolean tcpEnabled;
    private final boolean webSocketEnabled;

    /**
     * @param tcpEnabled       {@code SAM_TCP_ENABLED}
     * @param webSocketEnabled {@code SAM_WS_ENABLED}
     * @throws IllegalArgumentException si ambos están apagados (servidor inalcanzable)
     */
    public IngressPolicy(boolean tcpEnabled, boolean webSocketEnabled) {
        if (!tcpEnabled && !webSocketEnabled) {
            throw new IllegalArgumentException(
                "SAM_TCP_ENABLED y SAM_WS_ENABLED no pueden estar ambos en false: "
                    + "el servidor quedaría inalcanzable");
        }
        this.tcpEnabled = tcpEnabled;
        this.webSocketEnabled = webSocketEnabled;
    }

    public Action decide(Transport transport, Classification classification) {
        if (classification == Classification.NEED_MORE) {
            return Action.WAIT;
        }
        return switch (transport) {
            case INSIDE_WEBSOCKET -> classification == Classification.TLS ? Action.SAM_TLS : Action.CLOSE;
            case DIRECT_TCP -> decideDirect(classification);
        };
    }

    private Action decideDirect(Classification classification) {
        return switch (classification) {
            case HTTP -> webSocketEnabled ? Action.WEBSOCKET_HANDSHAKE : Action.CLOSE;
            case TLS -> tcpEnabled ? Action.SAM_TLS : Action.CLOSE;
            case LEGACY_PING, VANILLA -> tcpEnabled ? Action.VANILLA_RESTRICTED : Action.CLOSE;
            case NEED_MORE -> Action.WAIT;
        };
    }
}
