package dev.sam.common.net.gate;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import dev.sam.common.mc.LoginDisconnect;
import dev.sam.common.mc.Wire;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

/**
 * La compuerta de entrada en un pipeline de Netty real (PROTOCOLO.md 2.1 y 2.2, RF-AUTH-10):
 * clasifica la conexión, instala la ruta que corresponde, se quita y reenvía los bytes intactos.
 * Un cliente vanilla puede hacer ping de estado, pero al intentar entrar recibe SAM-K001.
 */
class IngressGateHandlerTest {

    private static final String KICK = "Este servidor requiere SAM Client: https://github.com/sam/releases [SAM-K001]";
    private static final byte[] HANDSHAKE_STATUS = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df01");
    private static final byte[] HANDSHAKE_LOGIN = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df02");
    private static final byte[] HANDSHAKE_TRANSFER = HexFormat.of().parseHex("1000ff05093132372e302e302e3163df03");
    /** Status request (id 0x00, sin cuerpo) que el cliente envía justo después del handshake. */
    private static final byte[] STATUS_REQUEST = {0x01, 0x00};
    private static final byte[] CLIENT_HELLO = {0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00};

    private Capture minecraft;
    private RecordingRoutes routes;

    @BeforeEach
    void setUp() {
        minecraft = new Capture();
        routes = new RecordingRoutes();
    }

    // ===== Cliente vanilla =====

    @Test
    void unPingDeEstadoVanillaLlegaIntactoAMinecraft() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(concat(HANDSHAKE_STATUS, STATUS_REQUEST)));
        assertThat(minecraft.bytes()).isEqualTo(concat(HANDSHAKE_STATUS, STATUS_REQUEST));
        assertThat(canal.isOpen()).isTrue();
        assertThat(canal.<Object>readOutbound()).isNull();
        assertThat(nombres(canal)).doesNotContain("sam_gate", "sam_vanilla_gate");
    }

    @Test
    void unLoginVanillaRecibeSamK001YSeCierraSinLlegarAMinecraft() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(HANDSHAKE_LOGIN));
        assertThat(salida(canal)).isEqualTo(LoginDisconnect.frame(KICK));
        assertThat(canal.isOpen()).isFalse();
        assertThat(minecraft.bytes()).isEmpty();
    }

    @Test
    void unTransferVanillaTambienSeExpulsa() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(HANDSHAKE_TRANSFER));
        assertThat(salida(canal)).isEqualTo(LoginDisconnect.frame(KICK));
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void elHandshakeFragmentadoEnVariosSegmentosSeArmaIgual() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        for (byte b : HANDSHAKE_LOGIN) {
            assertThat(canal.isOpen()).isTrue();
            canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {b}));
        }
        assertThat(salida(canal)).isEqualTo(LoginDisconnect.frame(KICK));
        assertThat(canal.isOpen()).isFalse();
    }

    @Property(tries = 100)
    void unPingDeEstadoPartidoEnCualquierPuntoLlegaIntacto(@ForAll @IntRange(min = 1, max = 18) int corte) {
        var datos = concat(HANDSHAKE_STATUS, STATUS_REQUEST);
        var captura = new Capture();
        var canal = new EmbeddedChannel();
        canal.pipeline().addLast("sam_gate", new IngressGateHandler(new IngressPolicy(true, false), Transport.DIRECT_TCP, new RecordingRoutes(), KICK));
        canal.pipeline().addLast("minecraft", captura);
        canal.writeInbound(Unpooled.wrappedBuffer(Arrays.copyOfRange(datos, 0, corte)));
        canal.writeInbound(Unpooled.wrappedBuffer(Arrays.copyOfRange(datos, corte, datos.length)));
        assertThat(captura.bytes()).isEqualTo(datos);
    }

    @Test
    void unPingLegacyLlegaIntactoAMinecraft() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        var legacy = new byte[] {(byte) 0xFE, 0x01, (byte) 0xFA};
        canal.writeInbound(Unpooled.wrappedBuffer(legacy));
        assertThat(minecraft.bytes()).isEqualTo(legacy);
        assertThat(canal.isOpen()).isTrue();
    }

    @Test
    void unHandshakeMalFormadoCierraLaConexion() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        // Frame de 3 bytes con id de paquete 0x05
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x03, 0x05, 0x00, 0x00}));
        assertThat(canal.isOpen()).isFalse();
        assertThat(minecraft.bytes()).isEmpty();
    }

    @Test
    void unHandshakeDemasiadoLargoSeCierraSinEsperarElCuerpo() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(Wire.varInt(VanillaLoginGate.MAX_HANDSHAKE_LENGTH + 1)));
        assertThat(canal.isOpen()).isFalse();
    }

    @Test
    void unHandshakeDelTamanoMaximoSeEsperaCompleto() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(Wire.varInt(VanillaLoginGate.MAX_HANDSHAKE_LENGTH)));
        assertThat(canal.isOpen()).isTrue();
    }

    @Test
    void unaLongitudDeFrameIncompletaEspera() {
        // Primer byte de un VarInt de 2 bytes (un handshake de más de 127 bytes que llega partido)
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {(byte) 0x80}));
        assertThat(canal.isOpen()).isTrue();
        assertThat(minecraft.bytes()).isEmpty();
        assertThat(nombres(canal)).contains("sam_vanilla_gate");
    }

    @Test
    void unaLongitudDeFrameNegativaCierraLaConexion() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(Wire.varInt(-1)));
        assertThat(canal.isOpen()).isFalse();
        assertThat(minecraft.bytes()).isEmpty();
    }

    @Test
    void elHandshakeMasChicoPosibleSeAceptaYUnoMenorSeCierra() {
        // id 0, protocolo 0, dirección vacía, puerto 25565, intent status: 6 bytes
        var minimo = new byte[] {0x06, 0x00, 0x00, 0x00, 0x63, (byte) 0xdd, 0x01};
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(minimo));
        assertThat(canal.isOpen()).isTrue();
        assertThat(minecraft.bytes()).isEqualTo(minimo);

        minecraft = new Capture();
        var corto = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        corto.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x05, 0x00, 0x00, 0x00, 0x63, (byte) 0xdd}));
        assertThat(corto.isOpen()).isFalse();
        assertThat(minecraft.bytes()).isEmpty();
    }

    @Test
    void unVarIntDeLongitudCorruptoCierraLaConexion() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x01}));
        assertThat(canal.isOpen()).isFalse();
    }

    // ===== Rutas de SAM =====

    @Test
    void unClientHelloVaALaRutaTlsConLosBytesIntactos() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(CLIENT_HELLO));
        assertThat(routes.calls).containsExactly("tls");
        assertThat(routes.capture.bytes()).isEqualTo(CLIENT_HELLO);
        assertThat(minecraft.bytes()).isEmpty();
        assertThat(nombres(canal)).doesNotContain("sam_gate");
    }

    @Test
    void unaPeticionHttpVaALaRutaWebSocketSiEstaHabilitado() {
        var canal = canal(new IngressPolicy(true, true), Transport.DIRECT_TCP);
        var get = "GET /ruta HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII);
        canal.writeInbound(Unpooled.wrappedBuffer(get));
        assertThat(routes.calls).containsExactly("websocket");
        assertThat(routes.capture.bytes()).isEqualTo(get);
    }

    @Test
    void unaPeticionHttpSinWebSocketCierraLaConexion() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer("GET /ruta HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII)));
        assertThat(canal.isOpen()).isFalse();
        assertThat(routes.calls).isEmpty();
        assertThat(minecraft.bytes()).isEmpty();
    }

    @Test
    void dentroDelTunelSoloAvanzaTls() {
        var tunel = canal(new IngressPolicy(true, true), Transport.INSIDE_WEBSOCKET);
        tunel.writeInbound(Unpooled.wrappedBuffer(HANDSHAKE_STATUS));
        assertThat(tunel.isOpen()).isFalse();
        assertThat(minecraft.bytes()).isEmpty();

        routes = new RecordingRoutes();
        var tls = canal(new IngressPolicy(true, true), Transport.INSIDE_WEBSOCKET);
        tls.writeInbound(Unpooled.wrappedBuffer(CLIENT_HELLO));
        assertThat(routes.calls).containsExactly("tls");
    }

    @Test
    void conPocosBytesEspera() {
        var canal = canal(new IngressPolicy(true, false), Transport.DIRECT_TCP);
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x16}));
        assertThat(canal.isOpen()).isTrue();
        assertThat(routes.calls).isEmpty();
        assertThat(nombres(canal)).contains("sam_gate");
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x03, 0x01}));
        assertThat(routes.calls).containsExactly("tls");
        assertThat(routes.capture.bytes()).containsExactly(0x16, 0x03, 0x01);
    }

    // ===== Helpers =====

    private EmbeddedChannel canal(IngressPolicy policy, Transport transport) {
        var canal = new EmbeddedChannel();
        canal.pipeline().addLast("sam_gate", new IngressGateHandler(policy, transport, routes, KICK));
        canal.pipeline().addLast("minecraft", minecraft);
        return canal;
    }

    private static byte[] salida(EmbeddedChannel canal) {
        var out = new ByteArrayOutputStream();
        ByteBuf buf;
        while ((buf = canal.readOutbound()) != null) {
            var bytes = new byte[buf.readableBytes()];
            buf.readBytes(bytes);
            buf.release();
            out.writeBytes(bytes);
        }
        return out.toByteArray();
    }

    private static List<String> nombres(EmbeddedChannel canal) {
        return canal.pipeline().names();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Recolecta los bytes que llegan (simula los handlers de Minecraft o de una ruta). */
    static final class Capture extends ChannelInboundHandlerAdapter {
        private final ByteArrayOutputStream received = new ByteArrayOutputStream();

        @Override
        public boolean isSharable() {
            return true;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            var buf = (ByteBuf) msg;
            var bytes = new byte[buf.readableBytes()];
            buf.readBytes(bytes);
            buf.release();
            received.writeBytes(bytes);
        }

        byte[] bytes() {
            return received.toByteArray();
        }
    }

    /** Rutas de prueba: registran la llamada e instalan un capturador tras la compuerta. */
    static final class RecordingRoutes implements IngressRoutes {
        final List<String> calls = new ArrayList<>();
        final Capture capture = new Capture();

        @Override
        public boolean installSamTls(ChannelHandlerContext gate) {
            calls.add("tls");
            gate.pipeline().addAfter(gate.name(), "sam_tls", capture);
            return true;
        }

        @Override
        public boolean installWebSocket(ChannelHandlerContext gate) {
            calls.add("websocket");
            gate.pipeline().addAfter(gate.name(), "sam_ws", capture);
            return true;
        }
    }
}
