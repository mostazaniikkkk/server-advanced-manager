package dev.sam.common.net.ws;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerIdentity;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.gate.IngressGate;
import dev.sam.common.net.gate.SamRoutes;
import dev.sam.common.net.tls.SamTls;
import dev.sam.common.net.tls.ServerCertificateObserver;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;

/**
 * El handshake WebSocket del cliente (PROTOCOLO.md 2.3): la petición que envía, la validación del
 * 101 y, contra el servidor real de SAM en memoria, el TLS de SAM dentro del túnel.
 */
class WebSocketClientHandshakeTest {

    private static final String RUTA = "/sam-ws_x1";
    private static final byte[] HANDSHAKE_STATUS = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df01");
    private static final byte[] STATUS_REQUEST = {0x01, 0x00};

    private static ServerIdentity identidad;

    @BeforeAll
    static void identidad() {
        identidad = ServerIdentity.generate(new SecureRandom(), Instant.now());
    }

    /** 16 bytes fijos: la clave es predecible. */
    static SecureRandom fijo() {
        return new SecureRandom() {
            private static final long serialVersionUID = 1L;

            @Override
            public void nextBytes(byte[] bytes) {
                Arrays.fill(bytes, (byte) 7);
            }
        };
    }

    private static final String CLAVE = Base64.getEncoder().encodeToString(filled(16, 7));

    private static byte[] filled(int n, int v) {
        var b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    private final List<String> fallas = new ArrayList<>();
    private final List<ChannelHandlerContext> mejorados = new ArrayList<>();

    /** Como en el cliente real: el handshake se agrega con el canal ya activo. */
    private EmbeddedChannel cliente(String host) {
        var canal = new EmbeddedChannel();
        canal.pipeline().addLast(WebSocketClientHandshake.NAME,
            new WebSocketClientHandshake(host, RUTA, fijo(), mejorados::add, fallas::add));
        return canal;
    }

    private static String respuesta101(String accept, String protocolo) {
        return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept
            + "\r\n" + (protocolo == null ? "" : "Sec-WebSocket-Protocol: " + protocolo + "\r\n") + "\r\n";
    }

    private static byte[] salida(EmbeddedChannel canal) {
        var out = new ByteArrayOutputStream();
        Object msg;
        while ((msg = canal.readOutbound()) != null) {
            out.writeBytes(ByteBufUtil.getBytes((ByteBuf) msg));
            ((ByteBuf) msg).release();
        }
        return out.toByteArray();
    }

    @Test
    void alActivarseEnviaLaPeticionDeUpgradeConElSubprotocoloDeSam() {
        var canal = cliente("mc.ejemplo.cl");
        var peticion = new String(salida(canal), StandardCharsets.US_ASCII);
        assertThat(peticion).isEqualTo("GET " + RUTA + " HTTP/1.1\r\nHost: mc.ejemplo.cl\r\nUpgrade: websocket\r\n"
            + "Connection: Upgrade\r\nSec-WebSocket-Key: " + CLAVE + "\r\nSec-WebSocket-Version: 13\r\n"
            + "Sec-WebSocket-Protocol: " + WebSocketUpgrade.SUBPROTOCOL + "\r\n\r\n");
        // Sin respuesta todavía, nada más sale ni se cierra
        assertThat(canal.isOpen()).isTrue();
        assertThat(mejorados).isEmpty();
    }

    @Test
    void con101ValidoQuedaElTunelYLoQueSigueAlEncabezadoPasa() {
        var canal = cliente("h");
        salida(canal);
        var cabecera = respuesta101(WebSocketUpgrade.acceptKey(CLAVE), "sam.v1").getBytes(StandardCharsets.US_ASCII);
        // Llega en dos partes y con el primer frame binario pegado: [0x82, 3, 'a','b','c']
        canal.writeInbound(Unpooled.wrappedBuffer(Arrays.copyOf(cabecera, 20)));
        assertThat(mejorados).isEmpty();
        var resto = new ByteArrayOutputStream();
        resto.writeBytes(Arrays.copyOfRange(cabecera, 20, cabecera.length));
        resto.writeBytes(new byte[] {(byte) 0x82, 3, 'a', 'b', 'c'});
        canal.writeInbound(Unpooled.wrappedBuffer(resto.toByteArray()));
        assertThat(mejorados).hasSize(1);
        assertThat(mejorados.get(0).name()).isEqualTo(WebSocketTunnel.NAME);
        assertThat(canal.pipeline().names()).doesNotContain(WebSocketClientHandshake.NAME)
            .contains(WebSocketTunnel.NAME);
        ByteBuf datos = canal.readInbound();
        assertThat(ByteBufUtil.getBytes(datos)).containsExactly('a', 'b', 'c');
        assertThat(fallas).isEmpty();
        // Lo que se escribe después sale como frame binario enmascarado (cliente)
        canal.writeOutbound(Unpooled.wrappedBuffer(new byte[] {1, 2}));
        var frame = salida(canal);
        assertThat(frame[0]).isEqualTo((byte) 0x82);
        assertThat(frame[1] & 0x80).as("con máscara").isEqualTo(0x80);
        assertThat(frame[1] & 0x7f).isEqualTo(2);
    }

    @Test
    void cualquierOtraRespuestaCierraYDiceElMotivo() {
        var acept = WebSocketUpgrade.acceptKey(CLAVE);
        var casos = List.of(
            List.of("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", "el servidor respondió «HTTP/1.1 404 Not Found» (¿ruta del WebSocket correcta?)"),
            List.of(respuesta101("AAAA", "sam.v1"), "aceptación WebSocket inválida"),
            List.of(respuesta101(acept, "otro"), "el servidor no aceptó el subprotocolo sam.v1"),
            List.of(respuesta101(acept, null), "el servidor no aceptó el subprotocolo sam.v1"),
            List.of(respuesta101(acept, "sam.v1").replace("Upgrade: websocket\r\n", ""), "el servidor no aceptó el upgrade a WebSocket"),
            List.of(respuesta101(acept, "sam.v1").replace("Connection: Upgrade\r\n", "Connection: keep-alive\r\n"),
                "el servidor no aceptó el upgrade a WebSocket"));
        for (var caso : casos) {
            fallas.clear();
            mejorados.clear();
            var canal = cliente("h");
            salida(canal);
            canal.writeInbound(Unpooled.wrappedBuffer(caso.get(0).getBytes(StandardCharsets.US_ASCII)));
            assertThat(fallas).as(caso.get(0)).containsExactly(caso.get(1));
            assertThat(canal.isOpen()).as(caso.get(0)).isFalse();
            assertThat(mejorados).isEmpty();
        }
    }

    @Test
    void siElProxyNoLlegaAlServidorLoDiceEnVezDeCulparALaRuta() {
        // 502/503/504 de cualquier proxy; 530 es el de Cloudflare cuando el túnel está caído
        for (var estado : List.of("502 Bad Gateway", "503 Service Unavailable", "504 Gateway Timeout", "530 ")) {
            fallas.clear();
            var canal = cliente("h");
            salida(canal);
            canal.writeInbound(Unpooled.wrappedBuffer(("HTTP/1.1 " + estado + "\r\nServer: cloudflare\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII)));
            assertThat(fallas).as(estado).containsExactly(
                "el servidor de Minecraft no está disponible detrás del proxy (respondió «HTTP/1.1 " + estado + "»)");
            assertThat(canal.isOpen()).as(estado).isFalse();
        }
        // Un 500 o un 5xx sin forma de estado no es "caído": se informa tal cual
        fallas.clear();
        var canal = cliente("h");
        salida(canal);
        canal.writeInbound(Unpooled.wrappedBuffer("HTTP/1.1 500 Internal Server Error\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
        assertThat(fallas).containsExactly("el servidor respondió «HTTP/1.1 500 Internal Server Error» (¿ruta del WebSocket correcta?)");
    }

    @Test
    void lasCabecerasSeLeenSinDistinguirMayusculasNiEspacios() {
        var canal = cliente("h");
        salida(canal);
        canal.writeInbound(Unpooled.wrappedBuffer(("HTTP/1.1 101 OK\r\nupgrade:WebSocket\r\nlinea sin dos puntos\r\nCONNECTION: keep-alive, Upgrade\r\n"
            + "sec-websocket-accept:   " + WebSocketUpgrade.acceptKey(CLAVE) + "  \r\nSEC-WEBSOCKET-PROTOCOL: sam.v1\r\n\r\n")
            .getBytes(StandardCharsets.US_ASCII)));
        assertThat(fallas).isEmpty();
        assertThat(mejorados).hasSize(1);
    }

    @Test
    void unaRespuestaVaciaSeRechaza() {
        var canal = cliente("h");
        salida(canal);
        canal.writeInbound(Unpooled.wrappedBuffer("\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
        assertThat(fallas).containsExactly("el servidor respondió «» (¿ruta del WebSocket correcta?)");
    }

    @Test
    void unaRespuestaSinFinDentroDelLimiteSeRechaza() {
        var canal = cliente("h");
        salida(canal);
        var justo = new byte[WebSocketClientHandshake.MAX_RESPONSE_BYTES];
        Arrays.fill(justo, (byte) 'x');
        canal.writeInbound(Unpooled.wrappedBuffer(justo));
        assertThat(canal.isOpen()).isTrue();
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {'x'}));
        assertThat(fallas).containsExactly("respuesta del handshake WebSocket demasiado larga");
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void contraElServidorDeSamElTlsDeSamFuncionaDentroDelTunel() {
        var servidor = new EmbeddedChannel();
        IngressGate.install(servidor.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP,
            new SamRoutes(identidad, Optional.of(RUTA)), "kick vanilla");
        var recibido = new ByteArrayOutputStream();
        servidor.pipeline().addLast("minecraft", new ChannelInboundHandlerAdapter() {
            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                recibido.writeBytes(ByteBufUtil.getBytes((ByteBuf) msg));
                ((ByteBuf) msg).release();
            }
        });
        var observador = new ServerCertificateObserver();
        var tls = new SslHandler(SamTls.clientEngine(observador, "h", 443));
        var cliente = new EmbeddedChannel();
        cliente.pipeline().addLast(WebSocketClientHandshake.NAME, new WebSocketClientHandshake("h", RUTA, new SecureRandom(),
            tunel -> tunel.pipeline().addAfter(tunel.name(), "sam_tls", tls), fallas::add));
        for (int i = 0; i < 30 && !tls.handshakeFuture().isDone(); i++) {
            transferir(cliente, servidor);
            transferir(servidor, cliente);
        }
        assertThat(fallas).isEmpty();
        assertThat(tls.handshakeFuture().isSuccess()).as("TLS de SAM por el túnel: %s", tls.handshakeFuture().cause()).isTrue();
        assertThat(tls.engine().getApplicationProtocol()).isEqualTo(SamTls.ALPN);
        assertThat(observador.observed()).hasValueSatisfying(o -> assertThat(o.serverId()).isEqualTo(identidad.serverId()));
        cliente.writeOutbound(Unpooled.wrappedBuffer(concat(HANDSHAKE_STATUS, STATUS_REQUEST)));
        transferir(cliente, servidor);
        assertThat(recibido.toByteArray()).isEqualTo(concat(HANDSHAKE_STATUS, STATUS_REQUEST));
    }

    private static void transferir(EmbeddedChannel desde, EmbeddedChannel hacia) {
        Object msg;
        while ((msg = desde.readOutbound()) != null) {
            hacia.writeInbound(msg);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
