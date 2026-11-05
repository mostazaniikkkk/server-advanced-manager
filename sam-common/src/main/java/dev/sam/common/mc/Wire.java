package dev.sam.common.mc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.CorruptedFrameException;

/** Tipos básicos del protocolo de red de Minecraft Java (VarInt, String, frames). */
public final class Wire {

    public static final int MAX_VARINT_BYTES = 5;

    /** @param size bytes que ocupa en el buffer (1 a 5) */
    public record VarInt(int value, int size) {
    }

    private Wire() {
    }

    public static byte[] varInt(int value) {
        var out = new ByteArrayOutputStream(MAX_VARINT_BYTES);
        var remaining = value;
        while ((remaining & ~0x7F) != 0) {
            out.write((remaining & 0x7F) | 0x80);
            remaining >>>= 7;
        }
        out.write(remaining);
        return out.toByteArray();
    }

    /**
     * Lee un VarInt sin mover el índice de lectura.
     *
     * @param offset posición relativa al índice de lectura actual
     * @return vacío si todavía faltan bytes
     * @throws CorruptedFrameException si ocupa más de 5 bytes
     */
    public static Optional<VarInt> peekVarInt(ByteBuf buf, int offset) {
        int value = 0;
        for (int i = 0; i < MAX_VARINT_BYTES; i++) {
            int index = buf.readerIndex() + offset + i;
            if (index >= buf.writerIndex()) {
                return Optional.empty();
            }
            byte b = buf.getByte(index);
            value |= (b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) {
                return Optional.of(new VarInt(value, i + 1));
            }
        }
        throw new CorruptedFrameException("VarInt de más de " + MAX_VARINT_BYTES + " bytes");
    }

    /**
     * Lee un VarInt y avanza el índice de lectura.
     *
     * @throws CorruptedFrameException si está truncado o es demasiado largo
     */
    static int readVarInt(ByteBuf buf) {
        var varInt = peekVarInt(buf, 0).orElseThrow(() -> new CorruptedFrameException("VarInt truncado"));
        buf.skipBytes(varInt.size());
        return varInt.value();
    }

    /** String de Minecraft: longitud en bytes UTF-8 como VarInt, seguida de los bytes. */
    public static byte[] string(String text) {
        var bytes = text.getBytes(StandardCharsets.UTF_8);
        return concat(varInt(bytes.length), bytes);
    }

    /** Frame sin compresión: longitud del cuerpo como VarInt, seguida del cuerpo. */
    public static byte[] frame(byte[] body) {
        return concat(varInt(body.length), body);
    }

    static byte[] concat(byte[] a, byte[] b) {
        var out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
