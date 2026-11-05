package dev.sam.common.net.gate;

import io.netty.channel.ChannelHandlerContext;

/**
 * Lo que la compuerta instala detrás de sí para las conexiones de SAM. Cada método agrega sus
 * handlers inmediatamente después de la compuerta ({@code gate.name()}); luego la compuerta se
 * quita y les reenvía los bytes recibidos.
 *
 * <p>Una ruta <b>no cierra la conexión por su cuenta</b>: si no puede atenderla devuelve
 * {@code false} y la compuerta descarta lo recibido y cierra. Así esos bytes nunca llegan a
 * Minecraft (si la ruta cerrara, al desarmarse el pipeline la compuerta los reenviaría).
 */
public interface IngressRoutes {

    /** TLS 1.3 de SAM (PROTOCOLO.md 3.2). @return si instaló la ruta */
    boolean installSamTls(ChannelHandlerContext gate);

    /** Handshake HTTP de WebSocket (PROTOCOLO.md 2.3). @return si instaló la ruta */
    boolean installWebSocket(ChannelHandlerContext gate);

    /** Rutas no disponibles todavía: la compuerta cierra esas conexiones (fallan cerrado). */
    static IngressRoutes closing() {
        return new IngressRoutes() {
            @Override
            public boolean installSamTls(ChannelHandlerContext gate) {
                return false;
            }

            @Override
            public boolean installWebSocket(ChannelHandlerContext gate) {
                return false;
            }
        };
    }
}
