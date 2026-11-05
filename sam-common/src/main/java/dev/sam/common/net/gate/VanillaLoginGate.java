package dev.sam.common.net.gate;

import java.util.List;

import dev.sam.common.mc.Handshake;
import dev.sam.common.mc.LoginDisconnect;
import dev.sam.common.mc.Wire;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.CorruptedFrameException;

/**
 * Camino vanilla restringido (PROTOCOLO.md 2.2, RF-AUTH-10): lee el handshake de un cliente sin
 * SAM. Con intent {@code status} se quita y deja pasar la conexión (el cliente ve el servidor en
 * su lista); con {@code login} o {@code transfer} responde la desconexión SAM-K001 y cierra, sin
 * que nada llegue a Minecraft. Cualquier handshake mal formado cierra la conexión.
 */
public final class VanillaLoginGate extends ByteToMessageDecoder {

    /** Un handshake real ocupa menos de 800 bytes (dirección de hasta 255 caracteres). */
    public static final int MAX_HANDSHAKE_LENGTH = 1024;
    /** El más chico posible: id (1) + protocolo (1) + dirección vacía (1) + puerto (2) + intent (1). */
    public static final int MIN_HANDSHAKE_LENGTH = 6;

    private final String kickMessage;

    public VanillaLoginGate(String kickMessage) {
        this.kickMessage = kickMessage;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        try {
            var length = Wire.peekVarInt(in, 0);
            if (length.isEmpty()) {
                return;
            }
            int frameLength = length.get().value();
            if (frameLength < MIN_HANDSHAKE_LENGTH || frameLength > MAX_HANDSHAKE_LENGTH) {
                close(ctx, in);
                return;
            }
            if (in.readableBytes() < length.get().size() + frameLength) {
                return;
            }
            var handshake = Handshake.parse(in.slice(in.readerIndex() + length.get().size(), frameLength));
            if (handshake.intent() == Handshake.Intent.STATUS) {
                ctx.pipeline().remove(this);
                return;
            }
            in.skipBytes(in.readableBytes());
            ctx.writeAndFlush(Unpooled.wrappedBuffer(LoginDisconnect.frame(kickMessage)))
                .addListener(ChannelFutureListener.CLOSE);
        } catch (CorruptedFrameException e) {
            close(ctx, in);
        }
    }

    private static void close(ChannelHandlerContext ctx, ByteBuf in) {
        in.skipBytes(in.readableBytes());
        ctx.close();
    }
}
