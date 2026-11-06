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

    /**
     * Un login offline de Minecraft 1.21.1 sobre un flujo ya abierto (con compresión si el servidor la
     * pide), contestando lo justo en login y configuration (plugin, ping, keep-alive), hasta que el
     * servidor desconecta. Devuelve el texto de la desconexión.
     */
    static String loginHastaDesconexion(InputStream in, java.util.function.Consumer<byte[]> enviar, String nick)
            throws IOException {
        enviar.accept(handshake(2));
        enviar.accept(loginStart(nick));
        var compresion = -1;
        var configuracion = false;
        while (true) {
            var paquete = leerPaquete(in, compresion);
            var buf = ByteBuffer.wrap(paquete);
            var id = leerVarInt(buf);
            if (!configuracion) {
                switch (id) {
                    case 0x00 -> {
                        return new String(paquete, StandardCharsets.UTF_8);
                    }
                    case 0x02 -> {
                        enviar.accept(empaquetar(compresion, Wire.varInt(0x03)));
                        configuracion = true;
                    }
                    case 0x03 -> compresion = leerVarInt(buf);
                    case 0x04 -> {
                        var mensaje = leerVarInt(buf);
                        enviar.accept(empaquetar(compresion, concat(Wire.varInt(0x02), Wire.varInt(mensaje), new byte[] {0})));
                    }
                    default -> { }
                }
            } else {
                switch (id) {
                    case 0x02 -> {
                        return new String(paquete, StandardCharsets.UTF_8);
                    }
                    case 0x04 -> enviar.accept(empaquetar(compresion, concat(Wire.varInt(0x04), resto(buf))));
                    case 0x05 -> enviar.accept(empaquetar(compresion, concat(Wire.varInt(0x05), resto(buf))));
                    default -> { }
                }
            }
        }
    }

    private static byte[] leerPaquete(InputStream in, int compresion) throws IOException {
        int longitud = leerVarInt(in);
        var cuerpo = in.readNBytes(longitud);
        if (cuerpo.length != longitud) {
            throw new EOFException("frame truncado");
        }
        if (compresion < 0) {
            return cuerpo;
        }
        var buf = ByteBuffer.wrap(cuerpo);
        var largo = leerVarInt(buf);
        var datos = resto(buf);
        if (largo == 0) {
            return datos;
        }
        var inflater = new java.util.zip.Inflater();
        inflater.setInput(datos);
        var salida = new byte[largo];
        try {
            inflater.inflate(salida);
        } catch (java.util.zip.DataFormatException e) {
            throw new IOException(e);
        } finally {
            inflater.end();
        }
        return salida;
    }

    private static byte[] empaquetar(int compresion, byte[] paquete) {
        return compresion < 0 ? Wire.frame(paquete) : Wire.frame(concat(Wire.varInt(0), paquete));
    }

    private static byte[] resto(ByteBuffer buf) {
        var resto = new byte[buf.remaining()];
        buf.get(resto);
        return resto;
    }

    static byte[] concat(byte[]... partes) {
        var salida = new java.io.ByteArrayOutputStream();
        for (var parte : partes) {
            salida.writeBytes(parte);
        }
        return salida.toByteArray();
    }
}
