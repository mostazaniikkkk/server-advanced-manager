package dev.sam.common.proto;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import io.netty.buffer.ByteBuf;

/**
 * Lectura estricta de un mensaje SAM (PROTOCOLO.md 4.1, RS-NET-11): toda longitud se valida contra
 * su máximo antes de reservar memoria, los enums fuera de rango y los bytes sobrantes son error.
 * Cualquier error es {@link ProtocolException} ({@value ProtocolException#MALFORMED}).
 */
public final class SamReader {

    private static final int VARINT_MAX_BYTES = 5;

    private final ByteBuf in;

    private SamReader(ByteBuf in) {
        this.in = in;
    }

    /**
     * Lee el mensaje completo: si es más grande que {@code maxBytes} se rechaza sin leerlo, y si
     * sobran bytes al final, también.
     */
    public static <T> T decode(ByteBuf in, int maxBytes, Function<SamReader, T> message) {
        if (in.readableBytes() > maxBytes) {
            throw ProtocolException.malformed("mensaje de " + in.readableBytes() + " bytes, máximo " + maxBytes);
        }
        var value = message.apply(new SamReader(in));
        if (in.isReadable()) {
            throw ProtocolException.malformed("sobran " + in.readableBytes() + " bytes al final del mensaje");
        }
        return value;
    }

    public int varInt() {
        var value = 0;
        for (int i = 0; i < VARINT_MAX_BYTES; i++) {
            var b = readByte();
            value |= (b & 0x7f) << (7 * i);
            if ((b & 0x80) == 0) {
                return value;
            }
        }
        throw ProtocolException.malformed("VarInt de más de 5 bytes");
    }

    public boolean bool() {
        return switch (readByte()) {
            case 0 -> false;
            case 1 -> true;
            default -> throw ProtocolException.malformed("booleano inválido");
        };
    }

    /** Exactamente {@code length} bytes. */
    public byte[] fixed(int length) {
        need(length);
        var bytes = new byte[length];
        in.readBytes(bytes);
        return bytes;
    }

    /** Prefijo VarInt y hasta {@code max} bytes. */
    public byte[] bytes(int max) {
        return fixed(length(max));
    }

    /** UTF-8 estricto, con prefijo VarInt de bytes, hasta {@code maxBytes}. */
    public String string(int maxBytes) {
        var decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes(maxBytes))).toString();
        } catch (CharacterCodingException e) {
            throw ProtocolException.malformed("texto no es UTF-8 válido");
        }
    }

    /** Ordinal VarInt dentro del rango del enum. */
    public <E extends Enum<E>> E enumValue(Class<E> type) {
        var values = type.getEnumConstants();
        var ordinal = varInt();
        if (ordinal < 0 || ordinal >= values.length) {
            throw ProtocolException.malformed("valor " + ordinal + " fuera de rango para " + type.getSimpleName());
        }
        return values[ordinal];
    }

    public <T> Optional<T> optional(Function<SamReader, T> element) {
        return bool() ? Optional.of(element.apply(this)) : Optional.empty();
    }

    /** Prefijo VarInt y hasta {@code max} elementos. */
    public <T> List<T> list(int max, Function<SamReader, T> element) {
        var size = length(max);
        var values = new ArrayList<T>(size);
        for (int i = 0; i < size; i++) {
            values.add(element.apply(this));
        }
        return List.copyOf(values);
    }

    private int length(int max) {
        var length = varInt();
        if (length < 0 || length > max) {
            throw ProtocolException.malformed("largo " + length + " fuera de 0.." + max);
        }
        return length;
    }

    private byte readByte() {
        need(1);
        return in.readByte();
    }

    private void need(int bytes) {
        if (in.readableBytes() < bytes) {
            throw ProtocolException.malformed("mensaje incompleto");
        }
    }
}
