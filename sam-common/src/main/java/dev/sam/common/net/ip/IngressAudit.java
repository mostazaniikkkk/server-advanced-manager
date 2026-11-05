package dev.sam.common.net.ip;

/**
 * Destino de los eventos de seguridad de la entrada (RS-WS-02): por ahora el log del servidor,
 * después la auditoría encadenada. Los mensajes nunca incluyen valores enviados por el cliente.
 */
@FunctionalInterface
public interface IngressAudit {

    IngressAudit NONE = message -> {
    };

    void record(String message);
}
