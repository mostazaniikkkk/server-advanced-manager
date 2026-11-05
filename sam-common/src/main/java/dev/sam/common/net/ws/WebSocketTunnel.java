package dev.sam.common.net.ws;

import java.util.concurrent.TimeUnit;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.ContinuationWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CorruptedWebSocketFrameException;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ScheduledFuture;

/**
 * Convierte los mensajes binarios de WebSocket en un flujo de bytes y viceversa (PROTOCOLO.md 2.3,
 * RS-WS-04). Solo mensajes binarios: texto, close o cualquier otro frame cierra la conexión. Los
 * ping se responden con pong. Un mensaje, sumando sus fragmentos, no pasa de {@link #MAX_MESSAGE}.
 */
public final class WebSocketTunnel extends ChannelDuplexHandler {

    public static final String NAME = "sam_ws_tunnel";
    /** {@code SAM_WS_MAX_MESSAGE} por defecto: 1 MiB. */
    public static final int MAX_MESSAGE = 1 << 20;
    /** Ping cada 20 s; sin pong durante 60 s (tres pings seguidos) se cierra (PROTOCOLO.md 2.3). */
    public static final java.time.Duration PING_INTERVAL = java.time.Duration.ofSeconds(20);
    public static final int MAX_UNANSWERED_PINGS = 3;

    private long messageBytes;
    private int unansweredPings;
    private ScheduledFuture<?> pinger;

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        long interval = PING_INTERVAL.toNanos();
        pinger = ctx.executor().scheduleAtFixedRate(() -> ping(ctx), interval, interval, TimeUnit.NANOSECONDS);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        pinger.cancel(false);
    }

    private void ping(ChannelHandlerContext ctx) {
        if (unansweredPings >= MAX_UNANSWERED_PINGS) {
            ctx.close();
            return;
        }
        unansweredPings++;
        ctx.writeAndFlush(new PingWebSocketFrame());
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof BinaryWebSocketFrame || msg instanceof ContinuationWebSocketFrame) {
            var frame = (WebSocketFrame) msg;
            messageBytes += frame.content().readableBytes();
            if (messageBytes > MAX_MESSAGE) {
                frame.release();
                ctx.close();
                return;
            }
            if (frame.isFinalFragment()) {
                messageBytes = 0;
            }
            ctx.fireChannelRead(frame.content());
        } else if (msg instanceof PingWebSocketFrame ping) {
            ctx.writeAndFlush(new PongWebSocketFrame(ping.content()));
        } else if (msg instanceof PongWebSocketFrame pong) {
            unansweredPings = 0;
            pong.release();
        } else {
            ReferenceCountUtil.release(msg);
            ctx.close();
        }
    }

    /**
     * Un frame corrupto (violación del protocolo, frame sin máscara o mayor al límite) cierra la conexión
     * sin respuesta y no se propaga: así un cliente no puede llenar el log de Minecraft de errores.
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (cause instanceof CorruptedWebSocketFrameException) {
            ctx.close();
            return;
        }
        ctx.fireExceptionCaught(cause);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        ctx.write(msg instanceof ByteBuf bytes ? new BinaryWebSocketFrame(bytes) : msg, promise);
    }
}
