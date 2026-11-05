package dev.sam.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.net.IngressPolicy.Action;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ProtocolDetector.Classification;

/**
 * Transporte desde la configuración (REQUERIMIENTOS.md 8.3, RF-WS-01/02/03): por defecto solo TCP;
 * el WebSocket exige su ruta. Valores inválidos no se interpretan: se rechazan (RF-CFG-04).
 */
class TransportConfigTest {

    @Test
    void porDefectoSoloTcpYSinWebSocket() {
        var config = TransportConfig.from(Map.of());
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.TLS)).isEqualTo(Action.SAM_TLS);
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.HTTP)).isEqualTo(Action.CLOSE);
        assertThat(config.webSocketPath()).isEmpty();
    }

    @Test
    void conWebSocketYRutaAceptaAmbos() {
        var config = TransportConfig.from(Map.of(TransportConfig.WS_ENABLED, "true", TransportConfig.WS_PATH, "/juego-ws"));
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.HTTP)).isEqualTo(Action.WEBSOCKET_HANDSHAKE);
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.TLS)).isEqualTo(Action.SAM_TLS);
        assertThat(config.webSocketPath()).contains("/juego-ws");
    }

    @Test
    void soloWebSocketApagaElTcpDirecto() {
        var config = TransportConfig.from(Map.of(TransportConfig.TCP_ENABLED, "false",
            TransportConfig.WS_ENABLED, "true", TransportConfig.WS_PATH, "/juego-ws"));
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.TLS)).isEqualTo(Action.CLOSE);
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.HTTP)).isEqualTo(Action.WEBSOCKET_HANDSHAKE);
    }

    @Test
    void laRutaSinWebSocketActivoSeIgnora() {
        var config = TransportConfig.from(Map.of(TransportConfig.WS_PATH, "/juego-ws"));
        assertThat(config.webSocketPath()).isEmpty();
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.HTTP)).isEqualTo(Action.CLOSE);
    }

    @Test
    void losBooleanosSeLeenSinDistinguirMayusculasNiEspacios() {
        var config = TransportConfig.from(Map.of(TransportConfig.TCP_ENABLED, " FALSE ",
            TransportConfig.WS_ENABLED, "True", TransportConfig.WS_PATH, " /juego-ws "));
        assertThat(config.policy().decide(Transport.DIRECT_TCP, Classification.TLS)).isEqualTo(Action.CLOSE);
        assertThat(config.webSocketPath()).contains("/juego-ws");
    }

    @Test
    void unBooleanoInvalidoSeRechazaNombrandoLaClave() {
        for (var malo : List.of("si", "1", "yes", "", "truee")) {
            assertThatThrownBy(() -> TransportConfig.from(Map.of(TransportConfig.WS_ENABLED, malo)))
                .as(malo).isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.WS_ENABLED);
            assertThatThrownBy(() -> TransportConfig.from(Map.of(TransportConfig.TCP_ENABLED, malo)))
                .as(malo).isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.TCP_ENABLED);
        }
    }

    @Test
    void webSocketSinRutaSeRechaza() {
        for (var valores : List.of(Map.of(TransportConfig.WS_ENABLED, "true"),
                Map.of(TransportConfig.WS_ENABLED, "true", TransportConfig.WS_PATH, "  "))) {
            assertThatThrownBy(() -> TransportConfig.from(valores))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.WS_PATH);
        }
    }

    @Test
    void unaRutaInseguraSeRechaza() {
        assertThatThrownBy(() -> TransportConfig.from(Map.of(TransportConfig.WS_ENABLED, "true", TransportConfig.WS_PATH, "/a b")))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.WS_PATH);
    }

    @Test
    void ambosApagadosSeRechaza() {
        assertThatThrownBy(() -> TransportConfig.from(Map.of(TransportConfig.TCP_ENABLED, "false")))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.TCP_ENABLED);
    }
}
