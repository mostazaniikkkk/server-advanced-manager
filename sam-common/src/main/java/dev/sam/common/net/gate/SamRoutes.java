package dev.sam.common.net.gate;

import java.util.Optional;

import dev.sam.common.identity.ServerIdentity;
import dev.sam.common.net.tls.SamTls;
import dev.sam.common.net.ws.WebSocketUpgrade;
import io.netty.channel.ChannelHandlerContext;

/**
 * Rutas reales de la compuerta (PROTOCOLO.md 2.1 y 3.2). La ruta TLS instala, detrás de la
 * compuerta: TLS 1.3 de SAM, el guardia de ALPN y, dentro del túnel, un filtro de handshake de
 * Minecraft. El ping de estado pasa a Minecraft; el login se rechaza con SAM-K006 hasta que exista
 * el módulo de autenticación, así nadie llega a jugar sin autenticarse. La ruta WebSocket
 * (PROTOCOLO.md 2.3) existe solo si hay {@code SAM_WS_PATH}: dentro del túnel vuelve a esta misma
 * ruta TLS.
 */
public final class SamRoutes implements IngressRoutes {

    public static final String TLS_NAME = "sam_tls";
    public static final String ALPN_GUARD_NAME = "sam_alpn_guard";
    public static final String LOGIN_UNAVAILABLE = "Inicio de sesión no disponible. [SAM-K006]";

    private final ServerIdentity identity;
    private final Optional<String> webSocketPath;

    /**
     * @param webSocketPath {@code SAM_WS_PATH}; vacío si el WebSocket no está configurado
     * @throws IllegalArgumentException si la ruta no es segura
     */
    public SamRoutes(ServerIdentity identity, Optional<String> webSocketPath) {
        this.identity = identity;
        this.webSocketPath = webSocketPath.map(WebSocketUpgrade::validatePath);
    }

    @Override
    public boolean installSamTls(ChannelHandlerContext gate) {
        var handlers = SamTls.serverHandlers(identity);
        var pipeline = gate.pipeline();
        // En orden inverso, todos inmediatamente después de la compuerta
        pipeline.addAfter(gate.name(), IngressGateHandler.VANILLA_GATE_NAME, new VanillaLoginGate(LOGIN_UNAVAILABLE));
        pipeline.addAfter(gate.name(), ALPN_GUARD_NAME, handlers[1]);
        pipeline.addAfter(gate.name(), TLS_NAME, handlers[0]);
        return true;
    }

    @Override
    public boolean installWebSocket(ChannelHandlerContext gate) {
        webSocketPath.ifPresent(path -> WebSocketUpgrade.install(gate, path, this));
        return webSocketPath.isPresent();
    }
}
