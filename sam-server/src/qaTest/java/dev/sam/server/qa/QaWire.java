package dev.sam.server.qa;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import dev.sam.common.mc.Wire;

/** Lo mínimo del protocolo de Minecraft 1.21.1 para las pruebas de punta a punta. */
final class QaWire {

    static final String HOST = "127.0.0.1";
    static final int PORT = Integer.getInteger("sam.qa.port", 25567);
    static final int PROTOCOL_1_21_1 = 767;
    static final byte[] STATUS_REQUEST = {0x01, 0x00};

    private QaWire() {
    }

    record Frame(int id, String texto) {
    }

    static Socket conectar() throws IOException {
        var socket = new Socket(HOST, PORT);
        socket.setSoTimeout(5000);
        return socket;
    }

    static byte[] handshake(int intent) {
        var cuerpo = ByteBuffer.allocate(64);
        cuerpo.put(Wire.varInt(0x00)).put(Wire.varInt(PROTOCOL_1_21_1)).put(Wire.string(HOST))
            .putShort((short) PORT).put(Wire.varInt(intent));
        return Wire.frame(java.util.Arrays.copyOf(cuerpo.array(), cuerpo.position()));
    }

    static byte[] loginStart(String nombre) {
        var uuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + nombre).getBytes(StandardCharsets.UTF_8));
        var cuerpo = ByteBuffer.allocate(64);
        cuerpo.put(Wire.varInt(0x00)).put(Wire.string(nombre))
            .putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits());
        return Wire.frame(java.util.Arrays.copyOf(cuerpo.array(), cuerpo.position()));
    }

    /** Lee un frame sin compresión: [VarInt longitud][VarInt id][resto]; el resto como texto. */
    static Frame leerFrame(InputStream in) throws IOException {
        int longitud = leerVarInt(in);
        var cuerpo = in.readNBytes(longitud);
        if (cuerpo.length != longitud) {
            throw new EOFException("frame truncado");
        }
        var buf = ByteBuffer.wrap(cuerpo);
        int id = leerVarInt(buf);
        var resto = new byte[buf.remaining()];
        buf.get(resto);
        return new Frame(id, new String(resto, StandardCharsets.UTF_8));
    }

    private static int leerVarInt(InputStream in) throws IOException {
        int valor = 0;
        for (int i = 0; i < 5; i++) {
            int b = in.read();
            if (b < 0) {
                throw new EOFException("el servidor cerró la conexión");
            }
            valor |= (b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) {
                return valor;
            }
        }
        throw new IOException("VarInt demasiado largo");
    }

    private static int leerVarInt(ByteBuffer buf) {
        int valor = 0;
        for (int i = 0; i < 5; i++) {
            int b = buf.get() & 0xFF;
            valor |= (b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) {
                return valor;
            }
        }
        throw new IllegalStateException("VarInt demasiado largo");
    }
}
