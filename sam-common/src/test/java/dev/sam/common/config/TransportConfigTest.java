package dev.sam.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.net.IngressPolicy.Action;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ProtocolDetector.Classification;
import dev.sam.common.net.ip.RealIpHeader;
import dev.sam.common.net.ip.RealIpTest;

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

    // ===== IP real (RS-WS-02) =====

    private static final java.util.Map<String, String> WS = Map.of(TransportConfig.WS_ENABLED, "true", TransportConfig.WS_PATH, "/juego-ws");

    private static java.util.Map<String, String> conWs(String... pares) {
        var valores = new java.util.HashMap<>(WS);
        for (int i = 0; i < pares.length; i += 2) {
            valores.put(pares[i], pares[i + 1]);
        }
        return valores;
    }

    @Test
    void porDefectoConfiaEnCloudflareYUsaCfConnectingIp() {
        var config = TransportConfig.from(WS);
        assertThat(config.trustedProxies().contains(RealIpTest.ip("162.158.10.20"))).isTrue();
        assertThat(config.trustedProxies().contains(RealIpTest.ip("10.0.0.5"))).isFalse();
        assertThat(config.realIpHeader()).isEqualTo(RealIpHeader.CF_CONNECTING_IP);
    }

    @Test
    void losProxiesYLaCabeceraSeConfiguran() {
        var config = TransportConfig.from(conWs(TransportConfig.TRUSTED_PROXIES, "10.0.0.0/8",
            TransportConfig.REAL_IP_HEADER, "X-Forwarded-For"));
        assertThat(config.trustedProxies().contains(RealIpTest.ip("10.0.0.5"))).isTrue();
        assertThat(config.trustedProxies().contains(RealIpTest.ip("162.158.10.20"))).isFalse();
        assertThat(config.realIpHeader()).isEqualTo(RealIpHeader.X_FORWARDED_FOR);
        var vacio = TransportConfig.from(conWs(TransportConfig.TRUSTED_PROXIES, ""));
        assertThat(vacio.trustedProxies().contains(RealIpTest.ip("162.158.10.20"))).as("vacío: ninguno").isFalse();
    }

    @Test
    void proxiesOCabeceraInvalidosSeRechazanNombrandoLaClave() {
        assertThatThrownBy(() -> TransportConfig.from(conWs(TransportConfig.TRUSTED_PROXIES, "10.0.0.0/33")))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.TRUSTED_PROXIES);
        assertThatThrownBy(() -> TransportConfig.from(conWs(TransportConfig.REAL_IP_HEADER, "X-Real-IP")))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.REAL_IP_HEADER);
    }

    @Test
    void elResolverDeIpUsaLaConfiguracionYLaAuditoria() {
        var audit = new RealIpTest.Auditoria();
        var realIp = TransportConfig.from(WS).realIp(audit);
        var cabeceras = new io.netty.handler.codec.http.DefaultHttpHeaders().add("CF-Connecting-IP", "203.0.113.7");
        assertThat(realIp.resolve(RealIpTest.ip("162.158.10.20"), cabeceras)).isEqualTo(RealIpTest.ip("203.0.113.7"));
        assertThat(realIp.resolve(RealIpTest.ip("198.51.100.9"), cabeceras)).isEqualTo(RealIpTest.ip("198.51.100.9"));
        assertThat(audit.eventos).hasSize(1);
    }

    // ===== Conexiones sin clasificar (PROTOCOLO.md 10) =====

    @Test
    void losLimitesDeConexionesSinClasificarSonOchoYDoscientosCincuentaYSeis() {
        var config = TransportConfig.from(Map.of());
        assertThat(config.unclassifiedPerIp()).isEqualTo(8);
        assertThat(config.unclassifiedGlobal()).isEqualTo(256);
    }

    @Test
    void losLimitesSeConfiguranConEnterosPositivos() {
        var config = TransportConfig.from(Map.of(TransportConfig.UNCLASSIFIED_PER_IP, " 3 ",
            TransportConfig.UNCLASSIFIED_GLOBAL, "40"));
        assertThat(config.unclassifiedPerIp()).isEqualTo(3);
        assertThat(config.unclassifiedGlobal()).isEqualTo(40);
        for (var malo : List.of("0", "-1", "x", "", "2.5")) {
            assertThatThrownBy(() -> TransportConfig.from(Map.of(TransportConfig.UNCLASSIFIED_PER_IP, malo)))
                .as(malo).isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.UNCLASSIFIED_PER_IP);
            assertThatThrownBy(() -> TransportConfig.from(Map.of(TransportConfig.UNCLASSIFIED_GLOBAL, malo)))
                .as(malo).isInstanceOf(IllegalArgumentException.class).hasMessageContaining(TransportConfig.UNCLASSIFIED_GLOBAL);
        }
    }

    @Test
    void elGuardiaUsaLosLimitesYNoCuentaPorIpALosProxies() {
        var guardia = TransportConfig.from(conWs(TransportConfig.UNCLASSIFIED_PER_IP, "1")).guard();
        var canal = RealIpTest.canalDesde(RealIpTest.ip("198.51.100.9"));
        assertThat(guardia.admit(canal)).isTrue();
        assertThat(guardia.admit(RealIpTest.canalDesde(RealIpTest.ip("198.51.100.9")))).isFalse();
        assertThat(guardia.admit(RealIpTest.canalDesde(RealIpTest.ip("162.158.10.20")))).isTrue();
        assertThat(guardia.admit(RealIpTest.canalDesde(RealIpTest.ip("162.158.10.20")))).isTrue();
    }

    @Test
    void sinWebSocketLosProxiesNoSeUsan() {
        var config = TransportConfig.from(Map.of(TransportConfig.TRUSTED_PROXIES, "10.0.0.0/33"));
        assertThat(config.trustedProxies().contains(RealIpTest.ip("162.158.10.20"))).isFalse();
    }
}
