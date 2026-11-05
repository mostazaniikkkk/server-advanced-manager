package dev.sam.common.net.gate;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;

/**
 * Instalación de la compuerta en un pipeline ya armado por Minecraft (ServerConnectionListener),
 * y rutas que fallan cerrado mientras TLS y WebSocket no estén implementados.
 */
class IngressGateInstallTest {

    private static final String KICK = "SAM-K001";

    @Test
    void laCompuertaQuedaPrimeraAntesQueLosHandlersDeMinecraft() {
        var canal = canalConPipelineDeMinecraft();
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, false), Transport.DIRECT_TCP, IngressRoutes.closing(), KICK);
        assertThat(canal.pipeline().names()).startsWith(IngressGateHandler.NAME, "timeout", "legacy_query", "splitter");
    }

    @Test
    void instalarDosVecesNoDuplicaLaCompuerta() {
        var canal = canalConPipelineDeMinecraft();
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, false), Transport.DIRECT_TCP, IngressRoutes.closing(), KICK);
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, false), Transport.DIRECT_TCP, IngressRoutes.closing(), KICK);
        assertThat(canal.pipeline().names().stream().filter(IngressGateHandler.NAME::equals)).hasSize(1);
    }

    @Test
    void lasRutasCerradasCierranUnaConexionTlsSinQueLlegueAMinecraft() {
        var canal = canalConPipelineDeMinecraft();
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, false), Transport.DIRECT_TCP, IngressRoutes.closing(), KICK);
        canal.writeInbound(Unpooled.wrappedBuffer(new byte[] {0x16, 0x03, 0x01, 0x00}));
        assertThat(canal.isOpen()).isFalse();
        assertThat(canal.<Object>readInbound()).isNull();
    }

    @Test
    void lasRutasCerradasCierranUnaConexionWebSocketSinQueLlegueAMinecraft() {
        var canal = canalConPipelineDeMinecraft();
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, true), Transport.DIRECT_TCP, IngressRoutes.closing(), KICK);
        canal.writeInbound(Unpooled.wrappedBuffer("GET / HTTP/1.1\r\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        assertThat(canal.isOpen()).isFalse();
        assertThat(canal.<Object>readInbound()).isNull();
    }

    @Test
    void conLaCompuertaInstaladaUnLoginVanillaRecibeElKick() {
        var canal = canalConPipelineDeMinecraft();
        IngressGate.install(canal.pipeline(), new IngressPolicy(true, false), Transport.DIRECT_TCP, IngressRoutes.closing(), KICK);
        canal.writeInbound(Unpooled.wrappedBuffer(HexFormat.of().parseHex("1000ff05093132372e302e302e3163df02")));
        assertThat(canal.isOpen()).isFalse();
        assertThat(canal.<Object>readOutbound()).isNotNull();
    }

    private static EmbeddedChannel canalConPipelineDeMinecraft() {
        var canal = new EmbeddedChannel();
        for (var nombre : new String[] {"timeout", "legacy_query", "splitter", "decoder", "prepender", "encoder", "packet_handler"}) {
            canal.pipeline().addLast(nombre, new ChannelInboundHandlerAdapter());
        }
        return canal;
    }
}
