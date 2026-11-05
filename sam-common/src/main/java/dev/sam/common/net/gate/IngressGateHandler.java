package dev.sam.common.net.gate;

import java.util.List;
import java.util.concurrent.TimeUnit;

import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ProtocolDetector;
import dev.sam.common.net.ProtocolDetector.Classification;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.concurrent.ScheduledFuture;

/**
 * Compuerta de entrada (RS-NET-06, PROTOCOLO.md 2.1): va primera en el pipeline de cada conexión,
 * la clasifica por sus primeros bytes ({@link ProtocolDetector}), decide con la
 * {@link IngressPolicy} e instala la ruta que corresponde. Después se quita: al hacerlo,
 * {@link ByteToMessageDecoder} reenvía intactos los bytes acumulados al siguiente handler.
 */
public final class IngressGateHandler extends ByteToMessageDecoder {

    public static final String NAME = "sam_gate";
    public static final String VANILLA_GATE_NAME = "sam_vanilla_gate";
    /** Plazo para clasificar la conexión por sus primeros bytes (PROTOCOLO.md 2.1). */
    public static final java.time.Duration CLASSIFY_TIMEOUT = java.time.Duration.ofSeconds(5);

    private final IngressPolicy policy;
    private final Transport transport;
    private final IngressRoutes routes;
    private final String kickMessage;
    private ScheduledFuture<?> timeout;

    /** @param kickMessage mensaje de la desconexión SAM-K001 para clientes sin SAM */
    public IngressGateHandler(IngressPolicy policy, Transport transport, IngressRoutes routes, String kickMessage) {
        this.policy = policy;
        this.transport = transport;
        this.routes = routes;
        this.kickMessage = kickMessage;
    }

    /** Si en {@link #CLASSIFY_TIMEOUT} no se pudo clasificar, descarta lo recibido y cierra. */
    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        timeout = ctx.executor().schedule(() -> close(ctx, internalBuffer()),
            CLASSIFY_TIMEOUT.toNanos(), TimeUnit.NANOSECONDS);
    }

    @Override
    protected void handlerRemoved0(ChannelHandlerContext ctx) {
        timeout.cancel(false);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        var prefix = new byte[Math.min(in.readableBytes(), ProtocolDetector.MAX_PREFIX)];
        in.getBytes(in.readerIndex(), prefix);
        var classification = ProtocolDetector.classify(prefix);
        switch (policy.decide(transport, classification)) {
            case WAIT -> {
                // faltan bytes: ByteToMessageDecoder los sigue acumulando
            }
            case CLOSE -> close(ctx, in);
            case SAM_TLS -> leaveOrClose(ctx, in, routes.installSamTls(ctx));
            case WEBSOCKET_HANDSHAKE -> leaveOrClose(ctx, in, routes.installWebSocket(ctx));
            case VANILLA_RESTRICTED -> {
                // El ping legacy (anterior a 1.7) no tiene handshake: lo atiende Minecraft directamente
                if (classification != Classification.LEGACY_PING) {
                    ctx.pipeline().addAfter(ctx.name(), VANILLA_GATE_NAME, new VanillaLoginGate(kickMessage));
                }
                ctx.pipeline().remove(this);
            }
        }
    }

    /** Si la ruta se instaló, se quita reenviándole los bytes; si no, descarta y cierra. */
    private void leaveOrClose(ChannelHandlerContext ctx, ByteBuf in, boolean installed) {
        if (installed) {
            ctx.pipeline().remove(this);
        } else {
            close(ctx, in);
        }
    }

    /** Descarta lo acumulado antes de cerrar: si no, al desarmarse el pipeline llegaría a Minecraft. */
    private static void close(ChannelHandlerContext ctx, ByteBuf in) {
        in.skipBytes(in.readableBytes());
        ctx.close();
    }
}
