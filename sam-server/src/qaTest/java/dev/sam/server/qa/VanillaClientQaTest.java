package dev.sam.server.qa;

import static org.assertj.core.api.Assertions.assertThat;

import static dev.sam.server.qa.QaWire.PROTOCOL_1_21_1;
import static dev.sam.server.qa.QaWire.STATUS_REQUEST;
import static dev.sam.server.qa.QaWire.conectar;
import static dev.sam.server.qa.QaWire.handshake;
import static dev.sam.server.qa.QaWire.leerFrame;
import static dev.sam.server.qa.QaWire.loginStart;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * De punta a punta contra QA Server SAM: un cliente vanilla (sin SAM) habla el protocolo de
 * Minecraft 1.21.1 por un socket real. Puede ver el servidor en su lista, pero no entrar.
 */
class VanillaClientQaTest {

    @Test
    void unPingDeEstadoVanillaVeElServidor() throws IOException {
        try (var socket = conectar()) {
            var out = socket.getOutputStream();
            out.write(handshake(1));
            out.write(QaWire.STATUS_REQUEST);
            out.flush();

            var respuesta = leerFrame(socket.getInputStream());
            assertThat(respuesta.id()).isZero();
            assertThat(respuesta.texto()).contains("SAM QA").contains("\"protocol\":" + PROTOCOL_1_21_1);
            // También en claro: así un cliente SAM sabe que debe conectar por TLS (PROTOCOLO.md 2.4)
            assertThat(respuesta.texto()).containsPattern("\"sam\":\\{\"v\":\"1\\.0\",\"id\":\"[0-9a-f]{32}\",\"tls\":true\\}");
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

    @Test
    void unaConexionMudaSeCierraALos5Segundos() throws IOException {
        try (var socket = conectar()) {
            socket.setSoTimeout(10_000);
            long inicio = System.nanoTime();
            assertThat(socket.getInputStream().read()).as("el servidor cierra la conexión muda").isEqualTo(-1);
            long ms = (System.nanoTime() - inicio) / 1_000_000;
            assertThat(ms).as("plazo de clasificación (PROTOCOLO.md 2.1)").isBetween(4_500L, 7_000L);
        }
    }

    @Test
    void conNueveConexionesSinClasificarDeUnaIpUnaSeCierraEnElActo() throws Exception {
        // Las conexiones se arman en event loops distintos: la rechazada es la que llega última al
        // guardia, no necesariamente la última que abrió el cliente
        var abiertas = new java.util.ArrayList<java.net.Socket>();
        try {
            for (int i = 0; i < 9; i++) {
                abiertas.add(conectar());
            }
            Thread.sleep(500);
            int cerradas = 0;
            for (var socket : abiertas) {
                socket.setSoTimeout(300);
                try {
                    if (socket.getInputStream().read() == -1) {
                        cerradas++;
                    }
                } catch (java.net.SocketTimeoutException abierta) {
                    // sigue abierta, esperando clasificarse
                } catch (IOException reset) {
                    cerradas++;
                }
            }
            assertThat(cerradas).as("una sola, mucho antes del plazo de 5 s").isEqualTo(1);
        } finally {
            for (var socket : abiertas) {
                socket.close();
            }
        }
        // Al cerrarse, liberan su lugar: el servidor vuelve a atender
        long limite = System.nanoTime() + 3_000_000_000L;
        while (true) {
            try (var socket = conectar()) {
                socket.getOutputStream().write(concat(handshake(1), STATUS_REQUEST));
                var respuesta = leerFrame(socket.getInputStream());
                assertThat(respuesta.texto()).contains("SAM QA");
                return;
            } catch (IOException todaviaLleno) {
                if (System.nanoTime() > limite) {
                    throw todaviaLleno;
                }
                Thread.sleep(100);
            }
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var todo = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, todo, a.length, b.length);
        return todo;
    }
}
