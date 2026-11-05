package dev.sam.server.qa;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import dev.sam.common.mc.Wire;

/**
 * De punta a punta contra QA Server SAM: un cliente vanilla (sin SAM) habla el protocolo de
 * Minecraft 1.21.1 por un socket real. Puede ver el servidor en su lista, pero no entrar.
 */
class VanillaClientQaTest {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = Integer.getInteger("sam.qa.port", 25567);
    private static final int PROTOCOL_1_21_1 = 767;

    @Test
    void unPingDeEstadoVanillaVeElServidor() throws IOException {
        try (var socket = conectar()) {
            var out = socket.getOutputStream();
            out.write(handshake(1));
            out.write(new byte[] {0x01, 0x00}); // status request
            out.flush();

            var respuesta = leerFrame(socket.getInputStream());
            assertThat(respuesta.id()).isZero();
            assertThat(respuesta.texto()).contains("SAM QA").contains("\"protocol\":" + PROTOCOL_1_21_1);
        }
    }

    @Test
    void unLoginVanillaRecibeSamK001YLaConexionSeCierra() throws IOException {
        try (var socket = conectar()) {
            var out = socket.getOutputStream();
            out.write(handshake(2));
            out.write(loginStart("QaVanilla"));
            out.flush();

            var in = socket.getInputStream();
            var respuesta = leerFrame(in);
            assertThat(respuesta.id()).as("id del primer paquete del servidor (0x00 = desconexión)").isZero();
            assertThat(respuesta.texto()).contains("SAM-K001");
            assertThat(in.read()).as("el servidor cierra la conexión tras el kick").isEqualTo(-1);
        }
    }

    // ===== Cliente mínimo =====

    private record Frame(int id, String texto) {
    }

    private static Socket conectar() throws IOException {
        var socket = new Socket(HOST, PORT);
        socket.setSoTimeout(5000);
        return socket;
    }

    private static byte[] handshake(int intent) {
        var cuerpo = ByteBuffer.allocate(64);
        cuerpo.put(Wire.varInt(0x00)).put(Wire.varInt(PROTOCOL_1_21_1)).put(Wire.string(HOST))
            .putShort((short) PORT).put(Wire.varInt(intent));
        return Wire.frame(java.util.Arrays.copyOf(cuerpo.array(), cuerpo.position()));
    }

    private static byte[] loginStart(String nombre) {
        var uuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + nombre).getBytes(StandardCharsets.UTF_8));
        var cuerpo = ByteBuffer.allocate(64);
        cuerpo.put(Wire.varInt(0x00)).put(Wire.string(nombre))
            .putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits());
        return Wire.frame(java.util.Arrays.copyOf(cuerpo.array(), cuerpo.position()));
    }

    /** Lee un frame sin compresión: [VarInt longitud][VarInt id][resto]; el resto como texto. */
    private static Frame leerFrame(InputStream in) throws IOException {
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
