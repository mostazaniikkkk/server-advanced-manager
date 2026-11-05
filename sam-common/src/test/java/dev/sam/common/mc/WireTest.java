package dev.sam.common.mc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;

/**
 * Formato de red de Minecraft Java 1.21.1. Vectores calculados con una implementación de
 * referencia en Python, independiente.
 */
class WireTest {

    @ParameterizedTest(name = "varint({0}) = {1}")
    @CsvSource({
        "0, 00", "1, 01", "127, 7f", "128, 8001", "255, ff01", "25565, ddc701",
        "2097151, ffff7f", "2147483647, ffffffff07", "-1, ffffffff0f",
    })
    void codificaYDecodificaVarInt(int valor, String hex) {
        assertThat(HexFormat.of().formatHex(Wire.varInt(valor))).isEqualTo(hex);
        var buf = Unpooled.wrappedBuffer(HexFormat.of().parseHex(hex));
        assertThat(Wire.peekVarInt(buf, 0)).contains(new Wire.VarInt(valor, hex.length() / 2));
    }

    @Test
    void peekNoMueveElIndiceDeLectura() {
        var buf = Unpooled.wrappedBuffer(new byte[] {(byte) 0xdd, (byte) 0xc7, 0x01, 0x05});
        buf.readByte();
        buf.readerIndex(0);
        assertThat(Wire.peekVarInt(buf, 0)).contains(new Wire.VarInt(25565, 3));
        assertThat(buf.readerIndex()).isZero();
        assertThat(Wire.peekVarInt(buf, 3)).contains(new Wire.VarInt(5, 1));
    }

    @Test
    void unVarIntIncompletoPideMasBytes() {
        assertThat(Wire.peekVarInt(Unpooled.wrappedBuffer(new byte[] {(byte) 0x80}), 0)).isEmpty();
        assertThat(Wire.peekVarInt(Unpooled.EMPTY_BUFFER, 0)).isEmpty();
        assertThat(Wire.peekVarInt(Unpooled.wrappedBuffer(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}), 0)).isEmpty();
    }

    @Test
    void unVarIntDeMasDeCincoBytesEsCorrupto() {
        var seis = Unpooled.wrappedBuffer(new byte[] {(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x01});
        assertThatThrownBy(() -> Wire.peekVarInt(seis, 0)).isInstanceOf(CorruptedFrameException.class);
    }

    @Property
    void idaYVueltaDeVarInt(@ForAll int valor) {
        var bytes = Wire.varInt(valor);
        assertThat(bytes.length).isBetween(1, 5);
        assertThat(Wire.peekVarInt(Unpooled.wrappedBuffer(bytes), 0)).contains(new Wire.VarInt(valor, bytes.length));
    }

    @Test
    void stringConPrefijoDeLongitud() {
        assertThat(HexFormat.of().formatHex(Wire.string("127.0.0.1"))).isEqualTo("093132372e302e302e31");
        assertThat(Wire.string("ñ")).containsExactly(0x02, 0xc3, 0xb1);
    }

    @Test
    void unFrameLlevaSuLongitudDelante() {
        assertThat(Wire.frame("ab".getBytes(StandardCharsets.US_ASCII))).containsExactly(0x02, 'a', 'b');
        assertThat(Wire.frame(new byte[0])).containsExactly(0x00);
    }
}
