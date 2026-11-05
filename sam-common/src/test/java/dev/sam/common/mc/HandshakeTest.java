package dev.sam.common.mc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import dev.sam.common.mc.Handshake.Intent;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;

/** Paquete de handshake (serverbound, id 0x00) de Minecraft 1.21.1. */
class HandshakeTest {

    /** Cuerpos (sin el VarInt de longitud) de los vectores de referencia: protocolo 767, 127.0.0.1:25567. */
    static final String STATUS = "00ff05093132372e302e302e3163df01";
    static final String LOGIN = "00ff05093132372e302e302e3163df02";
    static final String TRANSFER = "00ff05093132372e302e302e3163df03";

    @Test
    void leeUnHandshakeDeStatus() {
        assertThat(Handshake.parse(cuerpo(STATUS))).isEqualTo(new Handshake(767, "127.0.0.1", 25567, Intent.STATUS));
    }

    @Test
    void leeLoginYTransfer() {
        assertThat(Handshake.parse(cuerpo(LOGIN)).intent()).isEqualTo(Intent.LOGIN);
        assertThat(Handshake.parse(cuerpo(TRANSFER)).intent()).isEqualTo(Intent.TRANSFER);
    }

    @Test
    void elPuertoSeLeeSinSigno() {
        var cuerpo = Unpooled.buffer();
        cuerpo.writeBytes(Wire.varInt(0)).writeBytes(Wire.varInt(767)).writeBytes(Wire.string("h"));
        cuerpo.writeShort(65535).writeBytes(Wire.varInt(2));
        assertThat(Handshake.parse(cuerpo).port()).isEqualTo(65535);
    }

    @ParameterizedTest(name = "rechaza: {0}")
    @ValueSource(strings = {
        "01ff05093132372e302e302e3163df01",     // id de paquete distinto de 0x00
        "00ff05093132372e302e302e3163df00",     // intent 0
        "00ff05093132372e302e302e3163df04",     // intent 4
        "00ff05093132372e302e302e3163df0100",   // bytes sobrantes
        "00ff05093132372e302e302e3163df",       // truncado (sin intent)
        "00ff0509313237",                       // string truncado
        "00ff05",                               // sin dirección
        "",                                     // vacío
    })
    void rechazaHandshakesMalFormados(String hex) {
        assertThatThrownBy(() -> Handshake.parse(cuerpo(hex))).isInstanceOf(CorruptedFrameException.class);
    }

    @Test
    void rechazaUnPuertoTruncado() {
        var cuerpo = Unpooled.buffer().writeBytes(Wire.varInt(0)).writeBytes(Wire.varInt(767))
            .writeBytes(Wire.string("h")).writeByte(0x63);
        assertThatThrownBy(() -> Handshake.parse(cuerpo)).isInstanceOf(CorruptedFrameException.class);
    }

    @Test
    void unaLongitudDeDireccionEnormeFallaSinReservarMemoria() {
        var cuerpo = Unpooled.buffer().writeBytes(Wire.varInt(0)).writeBytes(Wire.varInt(767))
            .writeBytes(Wire.varInt(1 << 30)).writeBytes(new byte[] {1, 2, 3});
        assertThatThrownBy(() -> Handshake.parse(cuerpo)).isInstanceOf(CorruptedFrameException.class);
    }

    @Test
    void aceptaUnaDireccionVacia() {
        var cuerpo = Unpooled.buffer().writeBytes(Wire.varInt(0)).writeBytes(Wire.varInt(0))
            .writeBytes(Wire.string("")).writeShort(25565).writeBytes(Wire.varInt(1));
        assertThat(Handshake.parse(cuerpo)).isEqualTo(new Handshake(0, "", 25565, Intent.STATUS));
    }

    @Test
    void aceptaUnaDireccionDe255CaracteresDeTresBytes() {
        // 255 caracteres de 3 bytes en UTF-8 = 765 bytes, el máximo que admite Minecraft
        var direccion = "€".repeat(255);
        assertThat(Handshake.parse(conDireccion(direccion)).address()).isEqualTo(direccion);
        assertThatThrownBy(() -> Handshake.parse(conDireccion(direccion + "€"))).isInstanceOf(CorruptedFrameException.class);
    }

    @Test
    void rechazaDireccionesDeMasDe255Caracteres() {
        assertThat(Handshake.parse(conDireccion("a".repeat(255))).address()).hasSize(255);
        assertThatThrownBy(() -> Handshake.parse(conDireccion("a".repeat(256)))).isInstanceOf(CorruptedFrameException.class);
    }

    @Test
    void rechazaUnaLongitudDeStringNegativaOEnorme() {
        var negativa = Unpooled.buffer().writeBytes(Wire.varInt(0)).writeBytes(Wire.varInt(767)).writeBytes(Wire.varInt(-1));
        assertThatThrownBy(() -> Handshake.parse(negativa)).isInstanceOf(CorruptedFrameException.class);
    }

    @Test
    void rechazaUtf8Invalido() {
        var cuerpo = Unpooled.buffer().writeBytes(Wire.varInt(0)).writeBytes(Wire.varInt(767))
            .writeBytes(Wire.varInt(1)).writeByte(0xff).writeShort(1).writeBytes(Wire.varInt(1));
        assertThatThrownBy(() -> Handshake.parse(cuerpo)).isInstanceOf(CorruptedFrameException.class);
    }

    @Test
    void elIntentConoceSuNumero() {
        assertThat(Intent.STATUS.id()).isEqualTo(1);
        assertThat(Intent.LOGIN.id()).isEqualTo(2);
        assertThat(Intent.TRANSFER.id()).isEqualTo(3);
    }

    static ByteBuf cuerpo(String hex) {
        return Unpooled.wrappedBuffer(HexFormat.of().parseHex(hex));
    }

    private static ByteBuf conDireccion(String direccion) {
        var cuerpo = Unpooled.buffer();
        cuerpo.writeBytes(Wire.varInt(0)).writeBytes(Wire.varInt(767)).writeBytes(Wire.string(direccion));
        cuerpo.writeShort(25565).writeBytes(Wire.varInt(2));
        return cuerpo;
    }
}
