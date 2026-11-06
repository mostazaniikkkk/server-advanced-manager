package dev.sam.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerId;
import dev.sam.common.mc.Wire;

/** La sonda de estado (PROTOCOLO.md 2.4) contra un servidor falso en un socket real. */
class StatusProbeTest {

    private static final String ID = "45f6c09d17e093f73d707e48bed9de34";
    private static final String SAM = "{\"version\":{\"name\":\"1.21.1\",\"protocol\":767},\"sam\":{\"v\":\"1.0\",\"id\":\"" + ID
        + "\",\"tls\":true}}";

    /** Un servidor de una sola conexión: lee lo que llega y contesta con {@code respuesta(recibido)}. */
    private static java.util.Optional<StatusAdvert> conServidor(Function<byte[], byte[]> respuesta,
            Function<InetSocketAddress, java.util.Optional<StatusAdvert>> cliente) throws Exception {
        try (var servidor = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            // Si el cliente nunca conecta, el accept no espera para siempre
            servidor.setSoTimeout(3000);
            var recibido = CompletableFuture.supplyAsync(() -> {
                try (var socket = servidor.accept()) {
                    socket.setSoTimeout(2000);
                    var entrada = socket.getInputStream();
                    var leido = new java.io.ByteArrayOutputStream();
                    var buf = new byte[256];
                    // Handshake y status request pueden llegar en segmentos distintos: se lee hasta la petición [1, 0]
                    int n;
                    do {
                        n = entrada.read(buf);
                        leido.write(buf, 0, Math.max(n, 0));
                    } while (n > 0 && !terminaConPeticion(leido.toByteArray()));
                    var salida = respuesta.apply(leido.toByteArray());
                    if (salida != null) {
                        socket.getOutputStream().write(salida);
                        socket.getOutputStream().flush();
                        Thread.sleep(200);
                    }
                    return leido.toByteArray();
                } catch (IOException | InterruptedException e) {
                    return new byte[0];
                }
            });
            var resultado = cliente.apply(new InetSocketAddress(servidor.getInetAddress(), servidor.getLocalPort()));
            recibido.get(5, TimeUnit.SECONDS);
            return resultado;
        }
    }

    private static boolean terminaConPeticion(byte[] leido) {
        return leido.length > 2 && leido[leido.length - 2] == 0x01 && leido[leido.length - 1] == 0x00;
    }

    static byte[] respuestaDeEstado(String json) {
        var cuerpo = new java.io.ByteArrayOutputStream();
        cuerpo.writeBytes(Wire.varInt(0x00));
        cuerpo.writeBytes(Wire.string(json));
        return Wire.frame(cuerpo.toByteArray());
    }

    @Test
    void unServidorSamSeReconocePorSuAnuncio() throws Exception {
        var anuncio = conServidor(r -> respuestaDeEstado(SAM), a -> StatusProbe.probe("mi.servidor", a, 2000));
        assertThat(anuncio).contains(new StatusAdvert(ServerId.fromHex(ID)));
    }

    @Test
    void laSondaEnviaUnHandshakeDeEstadoYLaPeticion() throws Exception {
        var enviado = new byte[1][];
        var puertoUsado = new int[1];
        conServidor(r -> {
            enviado[0] = r;
            return respuestaDeEstado(SAM);
        }, a -> {
            puertoUsado[0] = a.getPort();
            return StatusProbe.probe("mi.servidor", a, 2000);
        });
        var cuerpo = new java.io.ByteArrayOutputStream();
        cuerpo.writeBytes(Wire.varInt(0x00));
        cuerpo.writeBytes(Wire.varInt(StatusProbe.PROTOCOL_1_21_1));
        cuerpo.writeBytes(Wire.string("mi.servidor"));
        cuerpo.write(0);
        cuerpo.write(0);
        cuerpo.writeBytes(Wire.varInt(1));
        var esperado = Wire.frame(cuerpo.toByteArray());
        assertThat(enviado[0]).hasSizeGreaterThan(esperado.length + 1);
        // El puerto va en el handshake, big-endian: se compara aparte
        var real = java.util.Arrays.copyOf(enviado[0], esperado.length);
        var puerto = ((real[esperado.length - 3] & 0xff) << 8) | (real[esperado.length - 2] & 0xff);
        assertThat(puerto).isEqualTo(puertoUsado[0]);
        real[esperado.length - 3] = 0;
        real[esperado.length - 2] = 0;
        assertThat(real).isEqualTo(esperado);
        assertThat(java.util.Arrays.copyOfRange(enviado[0], esperado.length, esperado.length + 2)).containsExactly(1, 0);
    }

    @Test
    void unServidorVanillaORarosNoSonSam() throws Exception {
        assertThat(conServidor(r -> respuestaDeEstado("{\"version\":{\"name\":\"1.21.1\",\"protocol\":767}}"),
            a -> StatusProbe.probe("h", a, 2000))).isEmpty();
        assertThat(conServidor(r -> "basura que no es minecraft".getBytes(StandardCharsets.US_ASCII),
            a -> StatusProbe.probe("h", a, 2000))).isEmpty();
        assertThat(conServidor(r -> new byte[0], a -> StatusProbe.probe("h", a, 2000))).isEmpty();
        // Otro id de paquete, o JSON inválido
        // Otro id de paquete, aunque traiga un anuncio válido
        var cuerpo = new java.io.ByteArrayOutputStream();
        cuerpo.writeBytes(Wire.varInt(0x05));
        cuerpo.writeBytes(Wire.string(SAM));
        var otroId = Wire.frame(cuerpo.toByteArray());
        assertThat(conServidor(r -> otroId, a -> StatusProbe.probe("h", a, 2000))).isEmpty();
        assertThat(conServidor(r -> respuestaDeEstado("{no json"), a -> StatusProbe.probe("h", a, 2000))).isEmpty();
    }

    @Test
    void unaRespuestaLargaSeLeeHastaElTopeVanillaYMasAllaNoSeAcepta() throws Exception {
        // Con relleno, la respuesta usa un largo de 3 bytes; el tope es el de vanilla (32767 caracteres de hasta 3 bytes)
        var maximo = 32767 * 3 + 16;
        // Largo del frame = id (1) + largo del texto (VarInt de 3 bytes) + texto
        var relleno = maximo - 4 - conRelleno(0).length();
        var justo = respuestaDeEstado(conRelleno(relleno));
        assertThat(conServidor(r -> justo, a -> StatusProbe.probe("h", a, 2000))).isPresent();
        var demasiado = respuestaDeEstado(conRelleno(relleno + 1));
        assertThat(conServidor(r -> demasiado, a -> StatusProbe.probe("h", a, 2000))).isEmpty();
    }

    /** El anuncio SAM con un campo de relleno de {@code n} caracteres. */
    private static String conRelleno(int n) {
        return SAM.substring(0, SAM.length() - 1) + ",\"x\":\"" + "a".repeat(n) + "\"}";
    }

    @Test
    void unServidorQueNoContestaNoTrabaLaConexion() throws Exception {
        // El servidor falso calla 3 s; la sonda (tope 300 ms) debe rendirse mucho antes. Se mide solo la sonda.
        var duracion = new long[1];
        var anuncio = conServidor(r -> {
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        }, a -> {
            var inicio = System.nanoTime();
            var resultado = StatusProbe.probe("h", a, 300);
            duracion[0] = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - inicio);
            return resultado;
        });
        assertThat(anuncio).isEmpty();
        assertThat(duracion[0]).isLessThan(1500);
    }

    @Test
    void unaDireccionSinServidorNoEsSam() throws Exception {
        int puerto;
        try (var libre = new ServerSocket(0)) {
            puerto = libre.getLocalPort();
        }
        assertThat(StatusProbe.probe("h", new InetSocketAddress("127.0.0.1", puerto), 500)).isEmpty();
    }
}
