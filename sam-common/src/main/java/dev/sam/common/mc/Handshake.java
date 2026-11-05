package dev.sam.common.mc;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.CorruptedFrameException;

/**
 * Paquete de handshake (serverbound, id 0x00): el primer paquete de toda conexión vanilla.
 * Lectura estricta: cualquier desviación es {@link CorruptedFrameException}.
 */
public record Handshake(int protocol, String address, int port, Intent intent) {

    /** Mismo límite que Minecraft para la dirección del servidor. */
    public static final int MAX_ADDRESS_LENGTH = 255;

    public enum Intent {
        STATUS(1), LOGIN(2), TRANSFER(3);

        private final int id;

        Intent(int id) {
            this.id = id;
        }

        public int id() {
            return id;
        }

        static Intent of(int id) {
            for (var intent : values()) {
                if (intent.id == id) {
                    return intent;
                }
            }
            throw new CorruptedFrameException("intent de handshake desconocido: " + id);
        }
    }

    /**
     * @param body el cuerpo del frame (sin el VarInt de longitud), consumido por completo
     * @throws CorruptedFrameException ante cualquier desviación, incluido un campo truncado
     */
    public static Handshake parse(ByteBuf body) {
        try {
            if (Wire.readVarInt(body) != 0x00) {
                throw new CorruptedFrameException("no es un paquete de handshake");
            }
            int protocol = Wire.readVarInt(body);
            var address = readAddress(body);
            int port = body.readUnsignedShort();
            var intent = Intent.of(Wire.readVarInt(body));
            if (body.isReadable()) {
                throw new CorruptedFrameException("bytes sobrantes tras el handshake");
            }
            return new Handshake(protocol, address, port, intent);
        } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
            // Campo truncado (readSlice/readUnsignedShort) o longitud negativa (readSlice)
            throw new CorruptedFrameException("handshake truncado o con longitudes inválidas", e);
        }
    }

    private static String readAddress(ByteBuf body) {
        // readSlice no reserva memoria: una longitud enorme falla sin riesgo de OutOfMemoryError
        var bytes = body.readSlice(Wire.readVarInt(body));
        String address;
        try {
            address = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(bytes.nioBuffer())
                .toString();
        } catch (CharacterCodingException e) {
            throw new CorruptedFrameException("dirección con UTF-8 inválido", e);
        }
        if (address.length() > MAX_ADDRESS_LENGTH) {
            throw new CorruptedFrameException("dirección de más de " + MAX_ADDRESS_LENGTH + " caracteres");
        }
        return address;
    }
}
