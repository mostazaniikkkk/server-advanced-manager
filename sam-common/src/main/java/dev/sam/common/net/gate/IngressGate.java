package dev.sam.common.net.gate;

import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import io.netty.channel.ChannelPipeline;

/** Instala la compuerta de entrada en el pipeline de una conexión recién aceptada. */
public final class IngressGate {

    private IngressGate() {
    }

    /**
     * Pone la compuerta <b>primera</b>, antes de los handlers de Minecraft (también antes de su
     * {@code timeout}: una conexión que se queda callada a mitad del handshake la corta igual el
     * timeout de Minecraft, porque no le llega ningún byte). Idempotente.
     */
    public static void install(ChannelPipeline pipeline, IngressPolicy policy, Transport transport, IngressRoutes routes,
            String kickMessage, ConnectionGuard guard) {
        if (pipeline.get(IngressGateHandler.NAME) == null) {
            pipeline.addFirst(IngressGateHandler.NAME, new IngressGateHandler(policy, transport, routes, kickMessage, guard));
        }
    }

    /** Sin límites de conexiones. */
    public static void install(ChannelPipeline pipeline, IngressPolicy policy, Transport transport, IngressRoutes routes,
            String kickMessage) {
        install(pipeline, policy, transport, routes, kickMessage, ConnectionGuard.unlimited());
    }
}
