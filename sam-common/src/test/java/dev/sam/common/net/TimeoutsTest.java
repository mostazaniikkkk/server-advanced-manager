package dev.sam.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerIdentity;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.gate.IngressGate;
import dev.sam.common.net.gate.IngressGateHandler;
import dev.sam.common.net.gate.IngressRoutes;
import dev.sam.common.net.gate.SamRoutes;
import dev.sam.common.net.tls.SamTls;
import dev.sam.common.net.ws.WebSocketTunnel;
import dev.sam.common.net.ws.WebSocketUpgrade;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameEncoder;
import io.netty.handler.ssl.SslHandler;

/**
 * Plazos de la conexión (PROTOCOLO.md 10): clasificar en 5 s, handshake de WebSocket en 5 s,
 * TLS en 10 s y ping de WebSocket cada 20 s con cierre a los 60 s sin pong. Un cliente lento no
 * puede retener una conexión sin clasificar (slowloris).
 */
class TimeoutsTest {

    private static final IngressRoutes ACEPTA = new IngressRoutes() {
        @Override
        public boolean installSamTls(ChannelHandlerContext gate) {
            return true;
        }

        @Override
        public boolean installWebSocket(ChannelHandlerContext gate) {
            return true;
        }
    };

    private static EmbeddedChannel conCompuerta(IngressRoutes routes) {
        var canal = new EmbeddedChannel();
        canal.freezeTime();
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP, routes, "kick");
        return canal;
    }

    private static void avanzar(EmbeddedChannel canal, Duration tiempo) {
        canal.advanceTimeBy(tiempo.toNanos(), TimeUnit.NANOSECONDS);
        canal.runScheduledPendingTasks();
    }

    private static final Duration UN_MS = Duration.ofMillis(1);
    private static final String CRLF = "\r\n";

    private static Object saliente(EmbeddedChannel canal) {
        return canal.readOutbound();
    }

    // ===== Compuerta =====

    @Test
    void sinBytesLaCompuertaCierraALos5Segundos() {
        var canal = conCompuerta(ACEPTA);
        avanzar(canal, IngressGateHandler.CLASSIFY_TIMEOUT.minus(UN_MS));
        assertThat(canal.isOpen()).isTrue();
        avanzar(canal, UN_MS);
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void conBytesInsuficientesTambienCierra() {
        var canal = conCompuerta(ACEPTA);
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x16}));
        avanzar(canal, IngressGateHandler.CLASSIFY_TIMEOUT);
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void unaVezClasificadaElPlazoDeLaCompuertaYaNoCorre() {
        var canal = conCompuerta(ACEPTA);
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x16, 0x03, 0x01, 0x00}));
        avanzar(canal, IngressGateHandler.CLASSIFY_TIMEOUT.multipliedBy(4));
        assertThat(canal.isOpen()).isTrue();
    }

    // ===== Handshake de WebSocket =====

    private static final String PETICION = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        + "Sec-WebSocket-Protocol: sam.v1\r\n\r\n";

    private static EmbeddedChannel conWebSocket() {
        return conCompuerta(new SamRoutes(ServerIdentity.generate(new SecureRandom(), Instant.now()), Optional.of("/ws")));
    }

    @Test
    void unHandshakeDeWebSocketIncompletoCierraALos5Segundos() {
        var canal = conWebSocket();
        canal.writeInbound(Unpooled.wrappedBuffer("GET /ws HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII)));
        avanzar(canal, WebSocketUpgrade.HANDSHAKE_TIMEOUT.minus(UN_MS));
        assertThat(canal.isOpen()).isTrue();
        avanzar(canal, UN_MS);
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void dentroDelTunelTambienHay5SegundosParaEmpezarElTls() {
        var canal = conWebSocket();
        canal.writeInbound(Unpooled.wrappedBuffer(PETICION.getBytes(StandardCharsets.US_ASCII)));
        assertThat(canal.pipeline().get(WebSocketTunnel.NAME)).isNotNull();
        avanzar(canal, IngressGateHandler.CLASSIFY_TIMEOUT.minus(UN_MS));
        assertThat(canal.isOpen()).isTrue();
        avanzar(canal, UN_MS);
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void trasEl101ElPlazoDelHandshakeYaNoCorre() {
        // Rutas que dejan pasar el TLS sin instalar nada: aislan el plazo del handshake del de TLS
        var canal = conCompuerta(new IngressRoutes() {
            @Override
            public boolean installSamTls(ChannelHandlerContext gate) {
                return true;
            }

            @Override
            public boolean installWebSocket(ChannelHandlerContext gate) {
                WebSocketUpgrade.install(gate, "/ws", this);
                return true;
            }
        });
        canal.writeInbound(Unpooled.wrappedBuffer(PETICION.getBytes(StandardCharsets.US_ASCII)));
        var frame = new EmbeddedChannel(new WebSocket13FrameEncoder(true));
        frame.writeOutbound(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[] {0x16, 0x03, 0x01, 0x00})));
        canal.writeInbound(saliente(frame));
        assertThat(canal.pipeline().get(WebSocketUpgrade.INNER_GATE_NAME)).isNull();
        avanzar(canal, WebSocketUpgrade.HANDSHAKE_TIMEOUT.multipliedBy(3));
        assertThat(canal.isOpen()).isTrue();
    }

    // ===== Nada de una conexión rechazada llega a Minecraft =====

    private static final class Minecraft extends io.netty.channel.ChannelInboundHandlerAdapter {
        int bytes;

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            bytes += ((io.netty.buffer.ByteBuf) msg).readableBytes();
            io.netty.util.ReferenceCountUtil.release(msg);
        }
    }

    private static Minecraft minecraftTras(EmbeddedChannel canal) {
        var minecraft = new Minecraft();
        canal.pipeline().addLast("minecraft", minecraft);
        return minecraft;
    }

    @Test
    void unaPeticionIncompletaQueVencePlazoNoDejaBytesParaMinecraft() {
        var canal = conWebSocket();
        var minecraft = minecraftTras(canal);
        canal.writeInbound(Unpooled.wrappedBuffer(("GET /ws HTTP/1.1" + CRLF + "Upgrade: webso").getBytes(StandardCharsets.US_ASCII)));
        avanzar(canal, WebSocketUpgrade.HANDSHAKE_TIMEOUT);
        assertThat(canal.isOpen()).isFalse();
        assertThat(minecraft.bytes).isZero();
    }

    @Test
    void unaPeticionDemasiadoGrandeNoDejaBytesParaMinecraft() {
        var canal = conWebSocket();
        var minecraft = minecraftTras(canal);
        canal.writeInbound(Unpooled.wrappedBuffer(("GET /ws HTTP/1.1" + CRLF + "X-Relleno: ").getBytes(StandardCharsets.US_ASCII)));
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[WebSocketUpgrade.MAX_REQUEST_BYTES]));
        assertThat(canal.isOpen()).isFalse();
        assertThat(minecraft.bytes).isZero();
    }

    @Test
    void lasSobrasDeUnaPeticionRechazadaNoLleganAMinecraft() {
        var canal = conWebSocket();
        var minecraft = minecraftTras(canal);
        var conOrigin = PETICION.replace(CRLF + CRLF, CRLF + "Origin: https://evil.example" + CRLF + CRLF) + "GET /otra HTTP/1.1";
        canal.writeInbound(Unpooled.wrappedBuffer(conOrigin.getBytes(StandardCharsets.US_ASCII)));
        assertThat(canal.isOpen()).isFalse();
        assertThat(minecraft.bytes).isZero();
    }

    @Test
    void unaConexionSinClasificarQueVencePlazoNoDejaBytesParaMinecraft() {
        var canal = conCompuerta(ACEPTA);
        var minecraft = minecraftTras(canal);
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x16}));
        avanzar(canal, IngressGateHandler.CLASSIFY_TIMEOUT);
        assertThat(canal.isOpen()).isFalse();
        assertThat(minecraft.bytes).isZero();
    }

    // ===== Ping del túnel =====

    @Test
    void elTunelHacePingCada20Segundos() {
        var tunel = new EmbeddedChannel();
        tunel.freezeTime();
        tunel.pipeline().addLast(new WebSocketTunnel());
        avanzar(tunel, WebSocketTunnel.PING_INTERVAL.minus(UN_MS));
        assertThat(saliente(tunel)).isNull();
        avanzar(tunel, UN_MS);
        assertThat(saliente(tunel)).isInstanceOf(PingWebSocketFrame.class);
        avanzar(tunel, WebSocketTunnel.PING_INTERVAL);
        assertThat(saliente(tunel)).isInstanceOf(PingWebSocketFrame.class);
    }

    @Test
    void sinPongDurante60SegundosElTunelCierra() {
        var tunel = new EmbeddedChannel();
        tunel.freezeTime();
        tunel.pipeline().addLast(new WebSocketTunnel());
        var primerPing = WebSocketTunnel.PING_INTERVAL;
        var limite = WebSocketTunnel.PING_INTERVAL.multipliedBy(WebSocketTunnel.MAX_UNANSWERED_PINGS);
        avanzar(tunel, primerPing.plus(limite).minus(UN_MS));
        assertThat(tunel.isOpen()).isTrue();
        avanzar(tunel, UN_MS);
        assertThat(tunel.isOpen()).isFalse();
    }

    @Test
    void unPongReiniciaLaCuenta() {
        var tunel = new EmbeddedChannel();
        tunel.freezeTime();
        tunel.pipeline().addLast(new WebSocketTunnel());
        for (int i = 0; i < 10; i++) {
            avanzar(tunel, WebSocketTunnel.PING_INTERVAL);
            tunel.writeInbound(new PongWebSocketFrame());
        }
        assertThat(tunel.isOpen()).isTrue();
    }

    @Test
    void alQuitarElTunelDejaDeHacerPing() {
        var tunel = new EmbeddedChannel();
        tunel.freezeTime();
        var handler = new WebSocketTunnel();
        tunel.pipeline().addLast(handler);
        tunel.pipeline().remove(handler);
        avanzar(tunel, WebSocketTunnel.PING_INTERVAL.multipliedBy(10));
        assertThat(saliente(tunel)).isNull();
        assertThat(tunel.isOpen()).isTrue();
    }

    // ===== TLS =====

    @Test
    void elHandshakeTlsDelServidorTiene10Segundos() {
        var ssl = (SslHandler) SamTls.serverHandlers(ServerIdentity.generate(new SecureRandom(), Instant.now()))[0];
        assertThat(ssl.getHandshakeTimeoutMillis()).isEqualTo(10_000);
    }
}
