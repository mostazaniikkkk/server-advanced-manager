package dev.sam.common.net.ws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerIdentity;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.gate.IngressGate;
import dev.sam.common.net.gate.IngressGateHandler;
import dev.sam.common.net.gate.SamRoutes;
import dev.sam.common.net.tls.SamTls;
import dev.sam.common.net.tls.ServerCertificateObserver;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.ContinuationWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameDecoder;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameEncoder;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.handler.ssl.SslHandler;

/**
 * Transporte WebSocket (PROTOCOLO.md 2.3, RF-WS-01/02, RS-WS-01/03/04/05): el handshake HTTP en el
 * mismo puerto, sus rechazos, y el túnel de mensajes binarios que solo admite el TLS de SAM.
 */
class WebSocketRouteTest {

    private static final String RUTA = "/sam-ws_x1";
    private static final String CLAVE_RFC = "dGhlIHNhbXBsZSBub25jZQ==";
    private static final byte[] HANDSHAKE_STATUS = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df01");
    private static final byte[] STATUS_REQUEST = {0x01, 0x00};

    private static ServerIdentity identidad;

    @BeforeAll
    static void identidad() {
        identidad = ServerIdentity.generate(new SecureRandom(), Instant.now());
    }

    // ===== Handshake HTTP =====

    @Test
    void laClaveDeAceptacionSigueElVectorDeRfc6455() {
        assertThat(WebSocketUpgrade.acceptKey(CLAVE_RFC)).isEqualTo("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    @Test
    void unaPeticionValidaRecibe101ConElSubprotocoloDeSam() {
        var servidor = servidor();
        var respuesta = enviarHttp(servidor, peticion());
        assertThat(respuesta).startsWith("HTTP/1.1 101 ");
        var cabeceras = respuesta.toLowerCase();
        assertThat(cabeceras).contains("upgrade: websocket\r\n").contains("connection: upgrade\r\n")
            .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=\r\n")
            .contains("sec-websocket-protocol: sam.v1\r\n");
        assertThat(servidor.isOpen()).isTrue();
        assertThat(servidor.pipeline().names())
            .containsSubsequence(WebSocketTunnel.NAME, WebSocketUpgrade.INNER_GATE_NAME, "minecraft")
            .doesNotContain(IngressGateHandler.NAME);
        assertThat(servidor.pipeline().toMap().values())
            .noneMatch(h -> h.getClass().getName().contains("HttpServerCodec"));
    }

    @Test
    void connectionAceptaUpgradeDentroDeUnaListaDeTokens() {
        var respuesta = enviarHttp(servidor(), peticion("Connection: keep-alive, Upgrade"));
        assertThat(respuesta).startsWith("HTTP/1.1 101 ");
    }

    @Test
    void lasCabecerasSeComparanSinDistinguirMayusculas() {
        var respuesta = enviarHttp(servidor(), peticion("upgrade: WebSocket", "CONNECTION: upgrade"));
        assertThat(respuesta).startsWith("HTTP/1.1 101 ");
    }

    @Test
    void conCabeceraOriginResponde403YCierraInclusoConOtraRuta() {
        var servidor = servidor();
        assertThat(enviarHttp(servidor, peticion("Origin: https://evil.example"))).startsWith("HTTP/1.1 403 ");
        assertThat(servidor.isOpen()).isFalse();
        var otro = servidor();
        assertThat(enviarHttp(otro, peticionEn("/otra", "Origin: https://evil.example"))).startsWith("HTTP/1.1 403 ");
    }

    @Test
    void conOtraRutaResponde404YCierra() {
        for (var ruta : List.of("/otra", RUTA + "?x=1", RUTA + "/", "/", RUTA.toUpperCase())) {
            var servidor = servidor();
            assertThat(enviarHttp(servidor, peticionEn(ruta))).as(ruta).startsWith("HTTP/1.1 404 ");
            assertThat(servidor.isOpen()).as(ruta).isFalse();
        }
    }

    @Test
    void unSubprotocoloAusenteODistintoResponde400() {
        for (var cabecera : List.of("Sec-WebSocket-Protocol: otro", "Sec-WebSocket-Protocol: sam.v1, otro",
                "Sec-WebSocket-Protocol: sam.v2", "Sec-WebSocket-Protocol:")) {
            var servidor = servidor();
            assertThat(enviarHttp(servidor, peticion(cabecera))).as(cabecera).startsWith("HTTP/1.1 400 ");
            assertThat(servidor.isOpen()).as(cabecera).isFalse();
        }
        var servidor = servidor();
        assertThat(enviarHttp(servidor, peticionSin("Sec-WebSocket-Protocol"))).startsWith("HTTP/1.1 400 ");
    }

    @Test
    void cabecerasDelHandshakeInvalidasResponden400() {
        var casos = List.of(
            peticion("Sec-WebSocket-Version: 8"),
            peticionSin("Sec-WebSocket-Version"),
            peticionSin("Sec-WebSocket-Key"),
            peticion("Sec-WebSocket-Key: AAAA"),
            peticion("Sec-WebSocket-Key: no es base64!!"),
            peticionSin("Upgrade"),
            peticion("Upgrade: h2c"),
            peticionSin("Connection"),
            peticion("Connection: keep-alive"),
            peticionConExtra("Sec-WebSocket-Key: " + CLAVE_RFC));
        for (var caso : casos) {
            var servidor = servidor();
            assertThat(enviarHttp(servidor, caso)).as(caso).startsWith("HTTP/1.1 400 ");
            assertThat(servidor.isOpen()).as(caso).isFalse();
        }
    }

    @Test
    void unaPeticionHttp10Responde400() {
        var servidor = servidor();
        assertThat(enviarHttp(servidor, peticion().replace("HTTP/1.1", "HTTP/1.0"))).startsWith("HTTP/1.1 400 ");
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void unaPeticionConCuerpoResponde400() {
        var servidor = servidor();
        var conCuerpo = peticionConExtra("Content-Length: 5") + "hola!";
        assertThat(enviarHttp(servidor, conCuerpo)).startsWith("HTTP/1.1 400 ");
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void unaPeticionDeMasDe8KiBSeCierraSinResponder101() {
        var servidor = servidor();
        var enorme = peticionConExtra("X-Relleno: " + "a".repeat(WebSocketUpgrade.MAX_REQUEST_BYTES));
        var respuesta = enviarHttp(servidor, enorme);
        assertThat(respuesta).doesNotContain("101");
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void unaPeticionJustoEnElLimiteSeAcepta() {
        var base = peticionConExtra("X-Relleno: ");
        var relleno = WebSocketUpgrade.MAX_REQUEST_BYTES - base.getBytes(StandardCharsets.US_ASCII).length;
        var justa = peticionConExtra("X-Relleno: " + "a".repeat(relleno));
        assertThat(justa.getBytes(StandardCharsets.US_ASCII)).hasSize(WebSocketUpgrade.MAX_REQUEST_BYTES);
        assertThat(enviarHttp(servidor(), justa)).startsWith("HTTP/1.1 101 ");
    }

    @Test
    void unaCabeceraMalFormadaResponde400() {
        var servidor = servidor();
        assertThat(enviarHttp(servidor, peticionConExtra("Nombre Invalido: x"))).startsWith("HTTP/1.1 400 ");
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void elLimiteSumaTodaLaPeticionAunqueLleguePorPartesYCadaParteQuepaEnElCodec() {
        // Ni la línea inicial ni las cabeceras superan por sí solas el límite del codec HTTP, pero juntas sí
        var servidor = servidor();
        var linea = "GET /" + "a".repeat(5000) + " HTTP/1.1\r\n";
        var cabeceras = String.join("\r\n", CABECERAS) + "\r\nX-Relleno: " + "b".repeat(4000) + "\r\n\r\n";
        servidor.writeInbound(Unpooled.wrappedBuffer(ascii(linea)));
        assertThat(servidor.isOpen()).isTrue();
        servidor.writeInbound(Unpooled.wrappedBuffer(ascii(cabeceras)));
        assertThat(salida(servidor)).as("se cierra sin responder, ni siquiera 404").isEmpty();
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void trasUnRechazoNoSeHaceElUpgradeAunqueLaRespuestaNoHayaSalido() {
        // En un socket real la respuesta sale después: el resto de la petición llega antes del cierre
        var servidor = servidor();
        var retenidas = new ArrayList<Object>();
        servidor.pipeline().addFirst(new ChannelOutboundHandlerAdapter() {
            @Override
            public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
                retenidas.add(msg);
            }
        });
        servidor.writeInbound(Unpooled.wrappedBuffer(ascii(peticion("Origin: https://evil.example"))));
        var texto = new StringBuilder();
        for (var msg : retenidas) {
            texto.append(new String(bytesDe((ByteBuf) msg), StandardCharsets.ISO_8859_1));
        }
        assertThat(texto.toString()).startsWith("HTTP/1.1 403 ").doesNotContain("101");
    }

    @Test
    void elUpgradeEsperaAlFinalDeLaPeticion() {
        var servidor = servidor();
        servidor.writeInbound(Unpooled.wrappedBuffer(ascii("GET ")));
        var http = servidor.pipeline().context(WebSocketUpgrade.HTTP_NAME);
        var request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, RUTA);
        for (var cabecera : CABECERAS) {
            request.headers().add(cabecera.substring(0, cabecera.indexOf(':')), cabecera.substring(cabecera.indexOf(':') + 1).trim());
        }
        http.fireChannelRead(request);
        http.fireChannelRead(new DefaultHttpContent(Unpooled.EMPTY_BUFFER));
        assertThat(salida(servidor)).as("todavía no termina la petición").isEmpty();
        http.fireChannelRead(LastHttpContent.EMPTY_LAST_CONTENT);
        assertThat(new String(salida(servidor), StandardCharsets.ISO_8859_1)).startsWith("HTTP/1.1 101 ");
    }

    @Test
    void sinRutaConfiguradaUnaPeticionHttpSeCierra() {
        var servidor = new EmbeddedChannel();
        IngressGate.install(servidor.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP,
            new SamRoutes(identidad, Optional.empty()), "kick");
        servidor.writeInbound(Unpooled.wrappedBuffer(ascii(peticion())));
        assertThat(salida(servidor)).isEmpty();
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void laRutaConfiguradaDebeSerUnaRutaSegura() {
        for (var mala : List.of("", "sin-barra", "/con espacio", "/con?query", "/" + "a".repeat(128), "/ñ", "/a#b")) {
            assertThatThrownBy(() -> WebSocketUpgrade.validatePath(mala)).as(mala).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new SamRoutes(identidad, Optional.of(mala))).as(mala).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(WebSocketUpgrade.validatePath("/" + "a".repeat(127))).hasSize(128);
        assertThat(WebSocketUpgrade.validatePath("/Az09-._~/x")).isEqualTo("/Az09-._~/x");
    }

    // ===== Túnel =====

    @Test
    void unMensajeDeTextoCierraElTunel() {
        var servidor = abierto();
        enviarFrame(servidor, new TextWebSocketFrame("hola"));
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void dentroDelTunelSoloSeAceptaTls() {
        var servidor = abierto();
        var minecraft = minecraft(servidor);
        enviarFrame(servidor, new BinaryWebSocketFrame(Unpooled.wrappedBuffer(concat(HANDSHAKE_STATUS, STATUS_REQUEST))));
        assertThat(servidor.isOpen()).isFalse();
        assertThat(minecraft.recibido.toByteArray()).isEmpty();
    }

    @Test
    void unPingRecibeUnPongConElMismoContenido() {
        var servidor = abierto();
        enviarFrame(servidor, new PingWebSocketFrame(Unpooled.wrappedBuffer(new byte[] {1, 2, 3})));
        var frames = framesDelServidor(servidor);
        assertThat(frames).hasSize(1);
        assertThat(frames.get(0)).isInstanceOf(PongWebSocketFrame.class);
        assertThat(contenido(frames.get(0))).containsExactly(1, 2, 3);
        assertThat(servidor.isOpen()).isTrue();
    }

    @Test
    void unPongNoHaceNada() {
        var servidor = abierto();
        enviarFrame(servidor, new PongWebSocketFrame(Unpooled.wrappedBuffer(new byte[] {9})));
        assertThat(framesDelServidor(servidor)).isEmpty();
        assertThat(servidor.isOpen()).isTrue();
    }

    @Test
    void unCloseCierraElTunel() {
        var servidor = abierto();
        enviarFrame(servidor, new CloseWebSocketFrame(1000, "chao"));
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void unMensajeFragmentadoQueSuperaElLimiteCierra() {
        var tunel = new EmbeddedChannel(new WebSocketTunnel());
        var mitad = WebSocketTunnel.MAX_MESSAGE / 2;
        tunel.writeInbound(new BinaryWebSocketFrame(false, 0, Unpooled.wrappedBuffer(new byte[mitad])));
        tunel.writeInbound(new ContinuationWebSocketFrame(false, 0, Unpooled.wrappedBuffer(new byte[mitad])));
        assertThat(tunel.isOpen()).isTrue();
        tunel.writeInbound(new ContinuationWebSocketFrame(true, 0, Unpooled.wrappedBuffer(new byte[1])));
        assertThat(tunel.isOpen()).isFalse();
        tunel.finishAndReleaseAll();
    }

    @Test
    void elLimiteSeReiniciaEnCadaMensaje() {
        var tunel = new EmbeddedChannel(new WebSocketTunnel());
        tunel.writeInbound(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[WebSocketTunnel.MAX_MESSAGE])));
        tunel.writeInbound(new BinaryWebSocketFrame(false, 0, Unpooled.wrappedBuffer(new byte[WebSocketTunnel.MAX_MESSAGE - 1])));
        tunel.writeInbound(new ContinuationWebSocketFrame(true, 0, Unpooled.wrappedBuffer(new byte[1])));
        assertThat(tunel.isOpen()).isTrue();
        long total = 0;
        Object msg;
        while ((msg = tunel.readInbound()) != null) {
            assertThat(msg).isInstanceOf(ByteBuf.class);
            total += ((ByteBuf) msg).readableBytes();
            ((ByteBuf) msg).release();
        }
        assertThat(total).isEqualTo(2L * WebSocketTunnel.MAX_MESSAGE);
    }

    @Test
    void elTunelEnvuelveLosBytesSalientesEnMensajesBinarios() {
        var tunel = new EmbeddedChannel(new WebSocketTunnel());
        tunel.writeOutbound(Unpooled.wrappedBuffer(new byte[] {4, 5}));
        Object salida = tunel.readOutbound();
        assertThat(salida).isInstanceOf(BinaryWebSocketFrame.class);
        assertThat(contenido((WebSocketFrame) salida)).containsExactly(4, 5);
        // Lo que no son bytes sigue de largo (por ejemplo, un pong ya armado)
        var pong = new PongWebSocketFrame();
        tunel.writeOutbound(pong);
        Object siguiente = tunel.readOutbound();
        assertThat(siguiente).isSameAs(pong);
    }

    @Test
    void unFrameMayorAlLimiteCierra() {
        var servidor = abierto();
        enviarFrame(servidor, new BinaryWebSocketFrame(Unpooled.wrappedBuffer(tlsRelleno(WebSocketTunnel.MAX_MESSAGE + 1))));
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void unFrameCorruptoNoLlegaComoExcepcionAMinecraft() {
        var servidor = abierto();
        var excepciones = new ArrayList<Throwable>();
        servidor.pipeline().addLast(new ChannelInboundHandlerAdapter() {
            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                excepciones.add(cause);
            }
        });
        enviarFrame(servidor, new BinaryWebSocketFrame(Unpooled.wrappedBuffer(tlsRelleno(WebSocketTunnel.MAX_MESSAGE + 1))));
        assertThat(servidor.isOpen()).isFalse();
        assertThat(excepciones).isEmpty();
    }

    @Test
    void otrasExcepcionesSiguenSuCamino() {
        var tunel = new EmbeddedChannel(new WebSocketTunnel());
        var error = new IllegalStateException("otra");
        tunel.pipeline().fireExceptionCaught(error);
        assertThatThrownBy(tunel::checkException).isSameAs(error);
    }

    @Test
    void unFrameSinMascaraDelClienteCierra() {
        var servidor = abierto();
        var sinMascara = new EmbeddedChannel(new WebSocket13FrameEncoder(false));
        sinMascara.writeOutbound(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(tlsRelleno(16))));
        servidor.writeInbound(Unpooled.wrappedBuffer(bytesDe(sinMascara)));
        assertThat(servidor.isOpen()).isFalse();
    }

    @Test
    void elTlsDeSamViajaDentroDelWebSocketYElPingDeEstadoLlegaAMinecraft() {
        var servidor = abierto();
        var observador = new ServerCertificateObserver();
        var tls = new SslHandler(SamTls.clientEngine(observador, "example.com", 443));
        var cliente = new EmbeddedChannel(new WebSocket13FrameEncoder(true),
            new WebSocket13FrameDecoder(false, false, 1 << 20), new WebSocketTunnel(), tls);
        for (int i = 0; i < 20 && !tls.handshakeFuture().isDone(); i++) {
            transferir(cliente, servidor);
            transferir(servidor, cliente);
        }
        assertThat(tls.handshakeFuture().isSuccess()).as("handshake TLS por WebSocket: %s", tls.handshakeFuture().cause()).isTrue();
        assertThat(observador.observed()).isPresent();
        cliente.writeOutbound(Unpooled.wrappedBuffer(concat(HANDSHAKE_STATUS, STATUS_REQUEST)));
        transferir(cliente, servidor);
        assertThat(minecraft(servidor).recibido.toByteArray()).isEqualTo(concat(HANDSHAKE_STATUS, STATUS_REQUEST));
        assertThat(servidor.pipeline().names())
            .containsSubsequence(WebSocketTunnel.NAME, SamRoutes.TLS_NAME, SamRoutes.ALPN_GUARD_NAME, "minecraft")
            .doesNotContain(WebSocketUpgrade.INNER_GATE_NAME);
    }

    // ===== Ayudantes =====

    private static final class Capture extends ChannelInboundHandlerAdapter {
        final ByteArrayOutputStream recibido = new ByteArrayOutputStream();

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            recibido.writeBytes(bytesDe((ByteBuf) msg));
        }
    }

    private static EmbeddedChannel servidor() {
        var servidor = new EmbeddedChannel();
        IngressGate.install(servidor.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP,
            new SamRoutes(identidad, Optional.of(RUTA)), "kick vanilla");
        servidor.pipeline().addLast("minecraft", new Capture());
        return servidor;
    }

    /** Un servidor con el WebSocket ya establecido. */
    private static EmbeddedChannel abierto() {
        var servidor = servidor();
        assertThat(enviarHttp(servidor, peticion())).startsWith("HTTP/1.1 101 ");
        return servidor;
    }

    /** Se toma antes de cerrar: al cerrarse, el pipeline se desarma. */
    private static Capture minecraft(EmbeddedChannel servidor) {
        return (Capture) servidor.pipeline().get("minecraft");
    }

    private static final List<String> CABECERAS = List.of(
        "Host: example.com",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: " + CLAVE_RFC,
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Protocol: sam.v1");

    private static String nombre(String cabecera) {
        return cabecera.substring(0, cabecera.indexOf(':')).toLowerCase();
    }

    /** La petición base, reemplazando las cabeceras del mismo nombre o agregándolas. */
    private static String peticion(String... reemplazos) {
        return peticionEn(RUTA, reemplazos);
    }

    private static String peticionEn(String ruta, String... reemplazos) {
        var cabeceras = new ArrayList<>(CABECERAS);
        for (var r : reemplazos) {
            int i = indice(cabeceras, nombre(r));
            if (i >= 0) {
                cabeceras.set(i, r);
            } else {
                cabeceras.add(r);
            }
        }
        return armar(ruta, cabeceras);
    }

    private static String peticionSin(String nombreCabecera) {
        var cabeceras = new ArrayList<>(CABECERAS);
        cabeceras.remove(indice(cabeceras, nombreCabecera.toLowerCase()));
        return armar(RUTA, cabeceras);
    }

    private static String peticionConExtra(String extra) {
        var cabeceras = new ArrayList<>(CABECERAS);
        cabeceras.add(extra);
        return armar(RUTA, cabeceras);
    }

    private static int indice(List<String> cabeceras, String nombre) {
        for (int i = 0; i < cabeceras.size(); i++) {
            if (nombre(cabeceras.get(i)).equals(nombre)) {
                return i;
            }
        }
        return -1;
    }

    private static String armar(String ruta, List<String> cabeceras) {
        return "GET " + ruta + " HTTP/1.1\r\n" + String.join("\r\n", cabeceras) + "\r\n\r\n";
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static String enviarHttp(EmbeddedChannel servidor, String peticion) {
        servidor.writeInbound(Unpooled.wrappedBuffer(ascii(peticion)));
        return new String(salida(servidor), StandardCharsets.ISO_8859_1);
    }

    private static byte[] salida(EmbeddedChannel canal) {
        var out = new ByteArrayOutputStream();
        Object msg;
        while ((msg = canal.readOutbound()) != null) {
            out.writeBytes(bytesDe((ByteBuf) msg));
        }
        return out.toByteArray();
    }

    private static void enviarFrame(EmbeddedChannel servidor, WebSocketFrame frame) {
        var codificador = new EmbeddedChannel(new WebSocket13FrameEncoder(true));
        codificador.writeOutbound(frame);
        var bytes = bytesDe(codificador);
        if (servidor.isOpen()) {
            servidor.writeInbound(Unpooled.wrappedBuffer(bytes));
        }
    }

    private static List<WebSocketFrame> framesDelServidor(EmbeddedChannel servidor) {
        var decodificador = new EmbeddedChannel(new WebSocket13FrameDecoder(false, false, 1 << 21));
        decodificador.writeInbound(Unpooled.wrappedBuffer(salida(servidor)));
        var frames = new ArrayList<WebSocketFrame>();
        Object msg;
        while ((msg = decodificador.readInbound()) != null) {
            frames.add((WebSocketFrame) msg);
        }
        return frames;
    }

    private static byte[] bytesDe(EmbeddedChannel canal) {
        return salida(canal);
    }

    private static byte[] bytesDe(ByteBuf buf) {
        var bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        buf.release();
        return bytes;
    }

    private static byte[] contenido(WebSocketFrame frame) {
        var bytes = new byte[frame.content().readableBytes()];
        frame.content().getBytes(frame.content().readerIndex(), bytes);
        return bytes;
    }

    /** Bytes que la compuerta clasifica como TLS (empiezan con 0x16 0x03). */
    private static byte[] tlsRelleno(int largo) {
        var bytes = new byte[largo];
        bytes[0] = 0x16;
        bytes[1] = 0x03;
        return bytes;
    }

    private static void transferir(EmbeddedChannel desde, EmbeddedChannel hacia) {
        Object msg;
        while ((msg = desde.readOutbound()) != null) {
            var bytes = bytesDe((ByteBuf) msg);
            if (hacia.isOpen()) {
                hacia.writeInbound(Unpooled.wrappedBuffer(bytes));
            }
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
