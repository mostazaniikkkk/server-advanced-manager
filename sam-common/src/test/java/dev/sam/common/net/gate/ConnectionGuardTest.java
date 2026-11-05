package dev.sam.common.net.gate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerIdentity;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ip.IngressAudit;
import dev.sam.common.net.ip.RealIpHeader;
import dev.sam.common.net.ip.RealIpResolver;
import dev.sam.common.net.ip.RealIpTest;
import dev.sam.common.net.ip.TrustedProxies;
import dev.sam.common.net.ws.WebSocketUpgrade;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameEncoder;

/**
 * Límites de conexiones sin clasificar (PROTOCOLO.md 10: 8 por IP y 256 en total) y de handshakes
 * WebSocket (RS-WS-03). Al excederlos, cierre inmediato. Una conexión deja de contar al
 * clasificarse o al cerrarse. Detrás de un proxy de confianza cuenta la IP real (RS-WS-02).
 */
class ConnectionGuardTest {

    private static final byte[] HANDSHAKE_STATUS = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df01");
    private static final InetAddress JUGADOR = RealIpTest.ip("198.51.100.9");
    private static final InetAddress OTRO = RealIpTest.ip("198.51.100.10");
    private static final InetAddress BORDE_CF = RealIpTest.ip("162.158.10.20");
    private static final InetAddress REAL = RealIpTest.ip("203.0.113.7");
    private static final String RUTA = "/ws";

    private static ServerIdentity identidad;

    @BeforeAll
    static void identidad() {
        identidad = ServerIdentity.generate(new SecureRandom(), Instant.now());
    }

    @Test
    void porDefectoOchoPorIpYDoscientosCincuentaYSeisEnTotal() {
        assertThat(ConnectionGuard.DEFAULT_PER_IP).isEqualTo(8);
        assertThat(ConnectionGuard.DEFAULT_GLOBAL).isEqualTo(256);
    }

    @Test
    void laConexionQueExcedeElLimitePorIpSeCierraEnElActo() {
        var guardia = guardia(8, 256);
        var abiertas = new ArrayList<EmbeddedChannel>();
        for (int i = 0; i < 8; i++) {
            abiertas.add(conectar(guardia, JUGADOR));
        }
        assertThat(abiertas).allMatch(EmbeddedChannel::isOpen);
        assertThat(guardia.pending(JUGADOR)).isEqualTo(8);
        var novena = conectar(guardia, JUGADOR);
        assertThat(novena.isOpen()).isFalse();
        assertThat(guardia.pending(JUGADOR)).as("la rechazada no cuenta").isEqualTo(8);
        assertThat(conectar(guardia, OTRO).isOpen()).as("otra IP no se ve afectada").isTrue();
        assertThat(guardia.pending()).isEqualTo(9);
    }

    @Test
    void elLimiteGlobalSeAplicaEntreIpsDistintas() {
        var guardia = guardia(8, 3);
        for (int i = 1; i <= 3; i++) {
            assertThat(conectar(guardia, RealIpTest.ip("198.51.100." + i)).isOpen()).isTrue();
        }
        assertThat(conectar(guardia, RealIpTest.ip("198.51.100.4")).isOpen()).isFalse();
        assertThat(guardia.pending()).isEqualTo(3);
    }

    @Test
    void alCerrarseUnaConexionLiberaSuLugar() {
        var guardia = guardia(1, 256);
        var primera = conectar(guardia, JUGADOR);
        assertThat(conectar(guardia, JUGADOR).isOpen()).isFalse();
        primera.close();
        assertThat(guardia.pending(JUGADOR)).isZero();
        assertThat(guardia.pending()).isZero();
        assertThat(conectar(guardia, JUGADOR).isOpen()).isTrue();
    }

    @Test
    void alClasificarseDejaDeContarAunqueSigaAbierta() {
        var guardia = guardia(1, 256);
        var vanilla = conectar(guardia, JUGADOR);
        vanilla.writeInbound(Unpooled.wrappedBuffer(HANDSHAKE_STATUS));
        assertThat(vanilla.isOpen()).isTrue();
        assertThat(vanilla.pipeline().get(IngressGateHandler.NAME)).isNull();
        assertThat(guardia.pending()).isZero();
        assertThat(conectar(guardia, JUGADOR).isOpen()).isTrue();
        vanilla.close();
        assertThat(guardia.pending()).as("cerrar después no descuenta dos veces").isEqualTo(1);
    }

    @Test
    void laConexionRechazadaSeCierraSinResponderNada() {
        var guardia = guardia(1, 256);
        conectar(guardia, JUGADOR);
        var rechazada = conectar(guardia, JUGADOR);
        assertThat(rechazada.isOpen()).as("cerrada antes de leer un byte").isFalse();
        Object salida = rechazada.readOutbound();
        assertThat(salida).as("ni kick ni respuesta").isNull();
        assertThat(rechazada.pipeline().get(IngressGateHandler.NAME)).isNull();
    }

    @Test
    void unProxyDeConfianzaSoloCuentaEnElTotal() {
        var guardia = guardia(2, 256);
        for (int i = 0; i < 5; i++) {
            assertThat(conectar(guardia, BORDE_CF).isOpen()).as("conexión %d", i).isTrue();
        }
        assertThat(guardia.pending(BORDE_CF)).isZero();
        assertThat(guardia.pending()).isEqualTo(5);
    }

    @Test
    void enElHandshakeWebSocketCuentaLaIpRealHastaQueEntraElTls() {
        var guardia = guardia(1, 256);
        var primera = conWebSocket(guardia, BORDE_CF);
        assertThat(enviarPeticion(primera, REAL)).startsWith("HTTP/1.1 101 ");
        assertThat(guardia.pending(REAL)).as("tras el 101 sigue sin clasificar").isEqualTo(1);
        assertThat(guardia.pending()).isEqualTo(1);

        var segunda = conWebSocket(guardia, BORDE_CF);
        assertThat(enviarPeticion(segunda, REAL)).as("misma IP real: sin respuesta").isEmpty();
        assertThat(segunda.isOpen()).isFalse();
        assertThat(guardia.pending()).isEqualTo(1);

        var otraIp = conWebSocket(guardia, BORDE_CF);
        assertThat(enviarPeticion(otraIp, RealIpTest.ip("203.0.113.8"))).startsWith("HTTP/1.1 101 ");
        assertThat(guardia.pending()).isEqualTo(2);

        enviarTls(primera);
        assertThat(primera.isOpen()).as("la compuerta interna conserva el lugar del handshake").isTrue();
        assertThat(primera.pipeline().get(WebSocketUpgrade.INNER_GATE_NAME)).isNull();
        assertThat(guardia.pending(REAL)).as("clasificada dentro del túnel").isZero();
        assertThat(guardia.pending()).isEqualTo(1);
        primera.close();
        otraIp.close();
        assertThat(guardia.pending()).isZero();
    }

    @Test
    void sinIpRealDeProxyLaConexionSigueContandoComoLaDelSocket() {
        var guardia = guardia(1, 256);
        var directa = conWebSocket(guardia, JUGADOR);
        assertThat(enviarPeticion(directa, null)).startsWith("HTTP/1.1 101 ");
        assertThat(guardia.pending(JUGADOR)).isEqualTo(1);
        assertThat(conectar(guardia, JUGADOR).isOpen()).isFalse();
    }

    @Test
    void cambiarALaMismaIpOAUnProxyNoCambiaLaCuenta() {
        var guardia = guardia(1, 256);
        var canal = conectar(guardia, JUGADOR);
        assertThat(ConnectionGuard.attribute(canal, JUGADOR)).isTrue();
        assertThat(guardia.pending(JUGADOR)).isEqualTo(1);
        assertThat(ConnectionGuard.attribute(canal, BORDE_CF)).isTrue();
        assertThat(guardia.pending(JUGADOR)).isZero();
        assertThat(guardia.pending(BORDE_CF)).as("un proxy no cuenta por IP").isZero();
        assertThat(guardia.pending()).isEqualTo(1);
        assertThat(ConnectionGuard.attribute(canal, OTRO)).isTrue();
        assertThat(guardia.pending(OTRO)).isEqualTo(1);
        ConnectionGuard.release(canal);
        assertThat(ConnectionGuard.attribute(canal, JUGADOR)).as("ya liberada").isTrue();
        assertThat(guardia.pending()).isZero();
        assertThat(guardia.pending(JUGADOR)).isZero();
    }

    @Test
    void unaConexionCerradaYaNoCambiaDeIp() {
        var guardia = guardia(1, 256);
        // Sin compuerta: el lugar lo libera solo el cierre y el canal lo sigue teniendo asociado
        var canal = RealIpTest.canalDesde(JUGADOR);
        assertThat(guardia.admit(canal)).isTrue();
        canal.close();
        assertThat(ConnectionGuard.attribute(canal, OTRO)).isTrue();
        assertThat(guardia.pending(OTRO)).isZero();
        assertThat(guardia.pending()).isZero();
    }

    @Test
    void lasCuentasBajanDeAUnaYNoQuedanIpsRegistradasSinConexiones() {
        var guardia = guardia(8, 256);
        var a = conectar(guardia, JUGADOR);
        var b = conectar(guardia, JUGADOR);
        var c = conectar(guardia, OTRO);
        assertThat(guardia.trackedIps()).isEqualTo(2);
        a.close();
        assertThat(guardia.pending(JUGADOR)).isEqualTo(1);
        assertThat(ConnectionGuard.attribute(b, OTRO)).isTrue();
        assertThat(guardia.pending(OTRO)).isEqualTo(2);
        assertThat(guardia.trackedIps()).isEqualTo(1);
        b.close();
        c.close();
        assertThat(guardia.trackedIps()).isZero();
        var sinLimite = ConnectionGuard.unlimited();
        sinLimite.admit(RealIpTest.canalDesde(JUGADOR));
        assertThat(sinLimite.trackedIps()).as("sin límites no registra IP").isZero();
    }

    @Test
    void unLimiteDeUnoEsValido() {
        var guardia = new ConnectionGuard(1, 1, ip -> false);
        assertThat(guardia.admit(RealIpTest.canalDesde(JUGADOR))).isTrue();
        assertThat(guardia.admit(RealIpTest.canalDesde(OTRO))).isFalse();
    }

    @Test
    void unaConexionSinGuardiaNoSeVeAfectada() {
        var canal = new EmbeddedChannel();
        assertThat(ConnectionGuard.attribute(canal, JUGADOR)).isTrue();
        ConnectionGuard.release(canal);
        assertThat(ConnectionGuard.unlimited().admit(canal)).isTrue();
    }

    @Test
    void losLimitesDebenSerPositivos() {
        for (var limites : List.of(new int[] {0, 1}, new int[] {1, 0}, new int[] {-1, 1})) {
            assertThatThrownBy(() -> new ConnectionGuard(limites[0], limites[1], ip -> false))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ===== Ayudantes =====

    private static ConnectionGuard guardia(int porIp, int global) {
        return new ConnectionGuard(porIp, global, TrustedProxies.parse("cloudflare")::contains);
    }

    /** Una conexión nueva con la compuerta y rutas que siempre cierran: queda sin clasificar. */
    private static EmbeddedChannel conectar(ConnectionGuard guardia, InetAddress ip) {
        var canal = RealIpTest.canalDesde(ip);
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP,
            IngressRoutes.closing(), "kick", guardia);
        return canal;
    }

    private static EmbeddedChannel conWebSocket(ConnectionGuard guardia, InetAddress ip) {
        var canal = RealIpTest.canalDesde(ip);
        var realIp = new RealIpResolver(TrustedProxies.parse("cloudflare"), RealIpHeader.CF_CONNECTING_IP, IngressAudit.NONE);
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP,
            new SamRoutes(identidad, Optional.of(RUTA), realIp), "kick", guardia);
        return canal;
    }

    private static String enviarPeticion(EmbeddedChannel canal, InetAddress real) {
        var peticion = "GET " + RUTA + " HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
            + "Sec-WebSocket-Protocol: sam.v1\r\n"
            + (real == null ? "" : "CF-Connecting-IP: " + real.getHostAddress() + "\r\n") + "\r\n";
        canal.writeInbound(Unpooled.wrappedBuffer(peticion.getBytes(StandardCharsets.US_ASCII)));
        var salida = new StringBuilder();
        Object msg;
        while ((msg = canal.readOutbound()) != null) {
            salida.append(((ByteBuf) msg).toString(StandardCharsets.ISO_8859_1));
            ((ByteBuf) msg).release();
        }
        return salida.toString();
    }

    /** El comienzo de un ClientHello dentro de un mensaje binario: la compuerta interna clasifica TLS. */
    private static void enviarTls(EmbeddedChannel canal) {
        var codificador = new EmbeddedChannel(new WebSocket13FrameEncoder(true));
        codificador.writeOutbound(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[] {0x16, 0x03, 0x01, 0x00})));
        Object frame = codificador.readOutbound();
        canal.writeInbound(frame);
    }
}
