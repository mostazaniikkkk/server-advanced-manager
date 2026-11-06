package dev.sam.common.net.gate;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;

import javax.net.ssl.SSLEngine;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerIdentity;
import dev.sam.common.mc.LoginDisconnect;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.tls.SamTls;
import dev.sam.common.net.tls.ServerCertificateObserver;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;

/**
 * La compuerta con la ruta TLS real (PROTOCOLO.md 2.1 y 3.2): un cliente SAM conecta por TLS 1.3 y
 * dentro habla el protocolo de Minecraft. El ping de estado llega a Minecraft; el login, mientras
 * no exista el módulo de autenticación, recibe SAM-K006 (nadie entra sin autenticarse).
 */
class SamRoutesTest {

    private static final byte[] HANDSHAKE_STATUS = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df01");
    private static final byte[] HANDSHAKE_LOGIN = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df02");
    private static final byte[] STATUS_REQUEST = {0x01, 0x00};

    private static ServerIdentity identidad;

    @BeforeAll
    static void identidad() {
        identidad = ServerIdentity.generate(new SecureRandom(), Instant.now());
    }

    @Test
    void unPingDeEstadoPorTlsLlegaDescifradoAMinecraft() {
        var conexion = new Conexion();
        assertThat(conexion.handshakeTls()).isTrue();
        conexion.enviar(concat(HANDSHAKE_STATUS, STATUS_REQUEST));
        assertThat(conexion.minecraft.bytes()).isEqualTo(concat(HANDSHAKE_STATUS, STATUS_REQUEST));
        assertThat(conexion.servidor.isOpen()).isTrue();
    }

    @Test
    void unLoginPorTlsRecibeSamK006MientrasNoHayaAutenticacion() {
        var conexion = new Conexion();
        assertThat(conexion.handshakeTls()).isTrue();
        conexion.enviar(HANDSHAKE_LOGIN);
        assertThat(conexion.recibido()).isEqualTo(LoginDisconnect.frame(SamRoutes.LOGIN_UNAVAILABLE));
        assertThat(conexion.minecraft.bytes()).isEmpty();
        assertThat(conexion.servidor.isOpen()).isFalse();
    }

    @Test
    void conLaAutenticacionDisponibleElLoginPorTlsLlegaAMinecraft() {
        var conexion = new Conexion(new SamRoutes(identidad, Optional.empty(), dev.sam.common.net.ip.RealIpResolver.direct(), true));
        assertThat(conexion.handshakeTls()).isTrue();
        conexion.enviar(HANDSHAKE_LOGIN);
        assertThat(conexion.minecraft.bytes()).isEqualTo(HANDSHAKE_LOGIN);
        assertThat(conexion.servidor.isOpen()).isTrue();
        assertThat(conexion.servidor.pipeline().names()).doesNotContain(IngressGateHandler.VANILLA_GATE_NAME)
            .containsSubsequence(SamRoutes.TLS_NAME, SamRoutes.ALPN_GUARD_NAME, "minecraft");
    }

    @Test
    void elMensajeDeLoginNoDisponibleLlevaSuCodigo() {
        assertThat(SamRoutes.LOGIN_UNAVAILABLE).contains("SAM-K006");
    }

    @Test
    void sinRutaWebSocketConfiguradaUnaPeticionHttpSeCierra() {
        var routes = new SamRoutes(identidad, Optional.empty());
        var canal = new EmbeddedChannel();
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP, routes, "kick");
        canal.writeInbound(Unpooled.wrappedBuffer("GET / HTTP/1.1\r\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void elPipelineQuedaEnElOrdenDelPerfil() {
        var conexion = new Conexion();
        assertThat(conexion.handshakeTls()).isTrue();
        assertThat(conexion.servidor.pipeline().names())
            .containsSubsequence(SamRoutes.TLS_NAME, SamRoutes.ALPN_GUARD_NAME, IngressGateHandler.VANILLA_GATE_NAME, "minecraft")
            .doesNotContain(IngressGateHandler.NAME);
    }

    // ===== Conexión cliente SAM ↔ servidor con compuerta, en memoria =====

    private static final class Conexion {
        final IngressGateHandlerTest.Capture minecraft = new IngressGateHandlerTest.Capture();
        final EmbeddedChannel servidor = new EmbeddedChannel();
        final SslHandler tlsCliente;
        final EmbeddedChannel cliente;

        Conexion() {
            this(new SamRoutes(identidad, Optional.empty()));
        }

        Conexion(SamRoutes rutas) {
            IngressGate.install(servidor.pipeline(), new IngressPolicy(true, false), Transport.DIRECT_TCP, rutas, "kick vanilla");
            servidor.pipeline().addLast("minecraft", minecraft);
            SSLEngine engine = SamTls.clientEngine(new ServerCertificateObserver(), "127.0.0.1", 25567);
            tlsCliente = new SslHandler(engine);
            cliente = new EmbeddedChannel(tlsCliente);
        }

        boolean handshakeTls() {
            for (int i = 0; i < 20 && !tlsCliente.handshakeFuture().isDone(); i++) {
                transferir(cliente, servidor);
                transferir(servidor, cliente);
            }
            return tlsCliente.handshakeFuture().isSuccess();
        }

        void enviar(byte[] datos) {
            cliente.writeOutbound(Unpooled.wrappedBuffer(datos));
            transferir(cliente, servidor);
            transferir(servidor, cliente);
        }

        byte[] recibido() {
            var out = new ByteArrayOutputStream();
            Object msg;
            while ((msg = cliente.readInbound()) != null) {
                var buf = (ByteBuf) msg;
                var bytes = new byte[buf.readableBytes()];
                buf.readBytes(bytes);
                buf.release();
                out.writeBytes(bytes);
            }
            return out.toByteArray();
        }

        private static void transferir(EmbeddedChannel desde, EmbeddedChannel hacia) {
            Object msg;
            while ((msg = desde.readOutbound()) != null) {
                var buf = (ByteBuf) msg;
                var bytes = new byte[buf.readableBytes()];
                buf.readBytes(bytes);
                buf.release();
                if (hacia.isOpen()) {
                    hacia.writeInbound(Unpooled.wrappedBuffer(bytes));
                }
            }
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
