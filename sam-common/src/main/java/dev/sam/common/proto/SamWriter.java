package dev.sam.common.proto;

import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;

import io.netty.buffer.ByteBuf;

/**
 * Escritura de un mensaje SAM con los mismos límites que {@link SamReader}: escribir algo fuera de
 * límite es un error de programación ({@link IllegalArgumentException}), nunca se trunca.
 */
public final class SamWriter {

    private final ByteBuf out;

    public SamWriter(ByteBuf out) {
        this.out = out;
    }

    public SamWriter varInt(int value) {
        var rest = value;
        while ((rest & ~0x7f) != 0) {
            out.writeByte((rest & 0x7f) | 0x80);
            rest >>>= 7;
        }
        out.writeByte(rest);
        return this;
    }

    public SamWriter bool(boolean value) {
        out.writeByte(value ? 1 : 0);
        return this;
    }

    public SamWriter fixed(byte[] value, int length) {
        if (value.length != length) {
            throw new IllegalArgumentException("se esperaban " + length + " bytes, no " + value.length);
        }
        out.writeBytes(value);
        return this;
    }

    public SamWriter bytes(byte[] value, int max) {
        checkLength(value.length, max);
        return varInt(value.length).fixed(value, value.length);
    }

    public SamWriter string(String value, int maxBytes) {
        var encoder = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
        byte[] bytes;
        try {
            var encoded = encoder.encode(CharBuffer.wrap(value));
            bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("texto no es UTF-8 válido", e);
        }
        return bytes(bytes, maxBytes);
    }

    public SamWriter enumValue(Enum<?> value) {
        return varInt(value.ordinal());
    }

    public <T> SamWriter optional(Optional<T> value, BiConsumer<SamWriter, T> element) {
        bool(value.isPresent());
        value.ifPresent(v -> element.accept(this, v));
        return this;
    }

    public <T> SamWriter list(List<T> values, int max, BiConsumer<SamWriter, T> element) {
        checkLength(values.size(), max);
        varInt(values.size());
        values.forEach(v -> element.accept(this, v));
        return this;
    }

    private static void checkLength(int length, int max) {
        if (length > max) {
            throw new IllegalArgumentException("largo " + length + " fuera de 0.." + max);
        }
    }
}
