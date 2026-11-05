package dev.sam.common.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import dev.sam.common.net.IngressPolicy.Action;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ProtocolDetector.Classification;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;

/**
 * PROTOCOLO.md 2.1 y 2.3, RF-WS-01, RF-WS-03, RS-WS-01: qué se hace con cada conexión
 * según su clasificación, el transporte por el que llegó y la configuración del servidor.
 */
class IngressPolicyTest {

    @ParameterizedTest(name = "TCP directo, TCP y WS activos: {0} → {1}")
    @CsvSource({
        "NEED_MORE,   WAIT",
        "TLS,         SAM_TLS",
        "HTTP,        WEBSOCKET_HANDSHAKE",
        "LEGACY_PING, VANILLA_RESTRICTED",
        "VANILLA,     VANILLA_RESTRICTED",
    })
    void tcpDirectoConTodoHabilitado(Classification clasificacion, Action esperada) {
        var politica = new IngressPolicy(true, true);
        assertThat(politica.decide(Transport.DIRECT_TCP, clasificacion)).isEqualTo(esperada);
    }

    @ParameterizedTest(name = "TCP directo, WS apagado: {0} → {1}")
    @CsvSource({
        "NEED_MORE,   WAIT",
        "TLS,         SAM_TLS",
        "HTTP,        CLOSE",
        "LEGACY_PING, VANILLA_RESTRICTED",
        "VANILLA,     VANILLA_RESTRICTED",
    })
    void sinWebSocketUnaPeticionHttpSeCierra(Classification clasificacion, Action esperada) {
        var politica = new IngressPolicy(true, false);
        assertThat(politica.decide(Transport.DIRECT_TCP, clasificacion)).isEqualTo(esperada);
    }

    @ParameterizedTest(name = "TCP directo, solo WS (RF-WS-03): {0} → {1}")
    @CsvSource({
        "NEED_MORE,   WAIT",
        "TLS,         CLOSE",
        "HTTP,        WEBSOCKET_HANDSHAKE",
        "LEGACY_PING, CLOSE",
        "VANILLA,     CLOSE",
    })
    void conTcpApagadoSoloSeAceptaElHandshakeWebSocket(Classification clasificacion, Action esperada) {
        var politica = new IngressPolicy(false, true);
        assertThat(politica.decide(Transport.DIRECT_TCP, clasificacion)).isEqualTo(esperada);
    }

    @ParameterizedTest(name = "Dentro del túnel WebSocket (RS-WS-01): {0} → {1}")
    @CsvSource({
        "NEED_MORE,   WAIT",
        "TLS,         SAM_TLS",
        "HTTP,        CLOSE",
        "LEGACY_PING, CLOSE",
        "VANILLA,     CLOSE",
    })
    void dentroDelTunelSoloSeAceptaTls(Classification clasificacion, Action esperada) {
        var politica = new IngressPolicy(false, true);
        assertThat(politica.decide(Transport.INSIDE_WEBSOCKET, clasificacion)).isEqualTo(esperada);
    }

    @Test
    void apagarTcpYWebSocketALaVezEsUnaConfiguracionInvalida() {
        // RF-CFG-04: una configuración que deja el servidor inalcanzable se rechaza al arrancar
        assertThatThrownBy(() -> new IngressPolicy(false, false))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("SAM_TCP_ENABLED")
            .hasMessageContaining("SAM_WS_ENABLED");
    }

    @Property
    void dentroDelTunelNadaQueNoSeaTlsAvanza(
            @ForAll Classification clasificacion, @ForAll boolean tcp) {
        var politica = new IngressPolicy(tcp, true);
        var accion = politica.decide(Transport.INSIDE_WEBSOCKET, clasificacion);
        assertThat(accion).isIn(Action.WAIT, Action.SAM_TLS, Action.CLOSE);
        if (clasificacion != Classification.TLS && clasificacion != Classification.NEED_MORE) {
            assertThat(accion).isEqualTo(Action.CLOSE);
        }
    }

    @Property
    void nuncaSeLlegaAlCaminoVanillaSinTcpDirectoHabilitado(
            @ForAll Transport transporte, @ForAll Classification clasificacion,
            @ForAll boolean tcp, @ForAll boolean ws) {
        if (!tcp && !ws) {
            return;
        }
        var accion = new IngressPolicy(tcp, ws).decide(transporte, clasificacion);
        if (accion == Action.VANILLA_RESTRICTED) {
            assertThat(transporte).isEqualTo(Transport.DIRECT_TCP);
            assertThat(tcp).isTrue();
        }
    }
}
