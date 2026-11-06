package dev.sam.common.net;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import dev.sam.common.mc.Wire;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;

/**
 * El ping de estado en claro con el que el cliente descubre si un servidor no fijado es SAM
 * (PROTOCOLO.md 2.4). Cualquier falla (sin respuesta, respuesta rara, cierre) cuenta como "no es
 * SAM": el cliente sigue en vanilla y, si el servidor era SAM, lo expulsa sin credenciales en juego.
 */
public final class StatusProbe {

    public static final int PROTOCOL_1_21_1 = 767;

    /** La respuesta de estado vanilla tiene como mucho 32767 caracteres (hasta 3 bytes cada uno). */
    private static final int MAX_RESPONSE = 32767 * 3 + 16;

    private StatusProbe() {
    }

    /** @param host el nombre que escribió el jugador (va en el handshake, como en vanilla) */
    public static Optional<StatusAdvert> probe(String host, InetSocketAddress address, int timeoutMillis) {
        try (var socket = new Socket()) {
            socket.connect(address, timeoutMillis);
            socket.setSoTimeout(timeoutMillis);
            var out = socket.getOutputStream();
            out.write(handshake(host, address.getPort()));
            // El stream del socket no tiene buffer: no hace falta flush
            out.write(new byte[] {0x01, 0x00});
            return StatusAdvert.read(JsonParser.parseString(readStatus(socket.getInputStream())));
        } catch (IOException | JsonParseException | IllegalStateException | CorruptedFrameException e) {
            return Optional.empty();
        }
    }

    private static byte[] handshake(String host, int port) {
        var body = new ByteArrayOutputStream();
        body.writeBytes(Wire.varInt(0x00));
        body.writeBytes(Wire.varInt(PROTOCOL_1_21_1));
        body.writeBytes(Wire.string(host));
        body.write(port >>> 8);
        body.write(port);
        body.writeBytes(Wire.varInt(1));
        return Wire.frame(body.toByteArray());
    }

    private static String readStatus(InputStream raw) throws IOException {
        var in = new DataInputStream(raw);
        var length = readVarInt(in);
        if (length > MAX_RESPONSE) {
            throw new IOException("respuesta de estado de largo " + length);
        }
        var frame = new DataInputStream(new java.io.ByteArrayInputStream(in.readNBytes(length)));
        if (readVarInt(frame) != 0x00) {
            throw new IOException("no es una respuesta de estado");
        }
        // Una respuesta truncada da un JSON inválido o sin anuncio: no es SAM
        return new String(frame.readNBytes(readVarInt(frame)), StandardCharsets.UTF_8);
    }

    /** Lee byte a byte hasta completar el VarInt; más de 5 bytes es error (CorruptedFrameException). */
    private static int readVarInt(DataInputStream in) throws IOException {
        var buf = Unpooled.buffer(Wire.MAX_VARINT_BYTES);
        Optional<Wire.VarInt> value;
        while ((value = Wire.peekVarInt(buf, 0)).isEmpty()) {
            buf.writeByte(in.readByte());
        }
        return value.get().value();
    }
}
