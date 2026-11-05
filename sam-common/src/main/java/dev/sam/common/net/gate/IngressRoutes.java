package dev.sam.common.net.gate;

import io.netty.channel.ChannelHandlerContext;

/**
 * Lo que la compuerta instala detrás de sí para las conexiones de SAM. Cada método agrega sus
 * handlers inmediatamente después de la compuerta ({@code gate.name()}); luego la compuerta se
 * quita y les reenvía los bytes recibidos.
 */
public interface IngressRoutes {

    /** TLS 1.3 de SAM (PROTOCOLO.md 3.2). */
    void installSamTls(ChannelHandlerContext gate);

    /** Handshake HTTP de WebSocket (PROTOCOLO.md 2.3). */
    void installWebSocket(ChannelHandlerContext gate);
}
