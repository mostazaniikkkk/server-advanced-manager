package dev.sam.server.qa;

import static org.assertj.core.api.Assertions.assertThat;

import static dev.sam.server.qa.QaWire.PROTOCOL_1_21_1;
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
}
