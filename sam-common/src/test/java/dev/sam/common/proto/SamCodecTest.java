package dev.sam.common.proto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;

/**
 * Codificación de los mensajes SAM (PROTOCOLO.md 4.1, RS-NET-11): lo que se escribe se lee igual, y
 * la lectura es estricta: longitudes contra su máximo antes de reservar, enums en rango, sin bytes
 * sobrantes. Todo error de lectura es SAM-P001.
 */
class SamCodecTest {

    enum Color { ROJO, VERDE, AZUL }

    static byte[] escribir(Consumer<SamWriter> mensaje) {
        var buf = Unpooled.buffer();
        mensaje.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    static <T> T leer(byte[] bytes, Function<SamReader, T> mensaje) {
        return SamReader.decode(Unpooled.wrappedBuffer(bytes), 512, mensaje);
    }

    static byte[] leerBytes(byte[] bytes, Function<SamReader, byte[]> mensaje) {
        return leer(bytes, mensaje);
    }

    static <T> T decodificar(io.netty.buffer.ByteBuf buf, int max, Function<SamReader, T> mensaje) {
        return SamReader.decode(buf, max, mensaje);
    }

    static byte[] b(int... valores) {
        var bytes = new byte[valores.length];
        for (int i = 0; i < valores.length; i++) {
            bytes[i] = (byte) valores[i];
        }
        return bytes;
    }

    private static void malFormado(byte[] bytes, Function<SamReader, ?> mensaje, String detalle) {
        assertThatThrownBy(() -> leer(bytes, mensaje))
            .isInstanceOfSatisfying(ProtocolException.class, e -> assertThat(e.code()).isEqualTo("SAM-P001"))
            .hasMessage(detalle);
    }

    @Property
    void unVarIntVaYVuelve(@ForAll int valor) {
        assertThat(SamCodecTest.<Integer>leer(escribir(w -> w.varInt(valor)), SamReader::varInt)).isEqualTo(valor);
    }

    @Test
    void elVarIntUsaElFormatoDeMinecraft() {
        assertThat(escribir(w -> w.varInt(0))).containsExactly(0);
        assertThat(escribir(w -> w.varInt(127))).containsExactly(0x7f);
        assertThat(escribir(w -> w.varInt(128))).containsExactly(0x80, 0x01);
        assertThat(escribir(w -> w.varInt(300))).containsExactly(0xac, 0x02);
        assertThat(escribir(w -> w.varInt(-1))).containsExactly(0xff, 0xff, 0xff, 0xff, 0x0f);
        assertThat(SamCodecTest.<Integer>leer(b(0xff, 0xff, 0xff, 0xff, 0x07), SamReader::varInt)).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void unVarIntDeMasDeCincoBytesOIncompletoEsMalFormado() {
        malFormado(b(0x80, 0x80, 0x80, 0x80, 0x80, 0x01), SamReader::varInt, "VarInt de más de 5 bytes");
        malFormado(b(0x80, 0x80), SamReader::varInt, "mensaje incompleto");
        malFormado(b(), SamReader::varInt, "mensaje incompleto");
    }

    @Test
    void unBooleanoSoloEsCeroOUno() {
        assertThat(SamCodecTest.<Boolean>leer(escribir(w -> w.bool(true)), SamReader::bool)).isTrue();
        assertThat(SamCodecTest.<Boolean>leer(escribir(w -> w.bool(false)), SamReader::bool)).isFalse();
        assertThat(escribir(w -> w.bool(true).bool(false))).containsExactly(1, 0);
        malFormado(b(2), SamReader::bool, "booleano inválido");
        malFormado(b(), SamReader::bool, "mensaje incompleto");
    }

    @Test
    void losBytesFijosTienenExactamenteSuLargo() {
        assertThat(leerBytes(escribir(w -> w.fixed(b(1, 2, 3), 3)), r -> r.fixed(3))).containsExactly(1, 2, 3);
        assertThat(escribir(w -> w.fixed(b(1, 2, 3), 3))).containsExactly(1, 2, 3);
        malFormado(b(1, 2), r -> r.fixed(3), "mensaje incompleto");
        assertThatThrownBy(() -> escribir(w -> w.fixed(b(1, 2), 3))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("se esperaban 3 bytes, no 2");
    }

    @Test
    void losBytesConLargoRespetanSuMaximo() {
        assertThat(escribir(w -> w.bytes(b(9, 8), 4))).containsExactly(2, 9, 8);
        assertThat(leerBytes(b(2, 9, 8), r -> r.bytes(4))).containsExactly(9, 8);
        assertThat(leerBytes(b(4, 1, 2, 3, 4), r -> r.bytes(4))).containsExactly(1, 2, 3, 4);
        assertThat(leerBytes(b(0), r -> r.bytes(4))).isEmpty();
        malFormado(b(5, 1, 2, 3, 4, 5), r -> r.bytes(4), "largo 5 fuera de 0..4");
        malFormado(b(0xff, 0xff, 0xff, 0xff, 0x0f), r -> r.bytes(4), "largo -1 fuera de 0..4");
        // Un largo enorme se rechaza por el máximo, sin reservar memoria para él
        malFormado(b(0xff, 0xff, 0xff, 0xff, 0x07), r -> r.bytes(Integer.MAX_VALUE), "mensaje incompleto");
        malFormado(b(3, 1, 2), r -> r.bytes(4), "mensaje incompleto");
        assertThatThrownBy(() -> escribir(w -> w.bytes(b(1, 2, 3), 2))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("largo 3 fuera de 0..2");
    }

    @Test
    void losTextosSonUtf8EstrictoYSuMaximoEsEnBytes() {
        assertThat(SamCodecTest.<String>leer(escribir(w -> w.string("año", 4)), r -> r.string(4))).isEqualTo("año");
        assertThat(escribir(w -> w.string("año", 4))).containsExactly(4, 'a', 0xc3, 0xb1, 'o');
        malFormado(escribir(w -> w.string("año", 4)), r -> r.string(3), "largo 4 fuera de 0..3");
        malFormado(b(2, 0xc3, 0x28), r -> r.string(8), "texto no es UTF-8 válido");
        malFormado(b(3, 0xed, 0xa0, 0x80), r -> r.string(8), "texto no es UTF-8 válido");
        assertThatThrownBy(() -> escribir(w -> w.string("año", 3))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("largo 4 fuera de 0..3");
        // Un texto que no se puede codificar no se escribe a medias
        assertThatThrownBy(() -> escribir(w -> w.string("a\uD800", 8))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("texto no es UTF-8 válido");
        assertThat(SamCodecTest.<String>leer(escribir(w -> w.string("", 0)), r -> r.string(0))).isEmpty();
    }

    @Test
    void losEnumsVanPorOrdinalYFueraDeRangoSonMalFormados() {
        assertThat(escribir(w -> w.enumValue(Color.AZUL))).containsExactly(2);
        assertThat(SamCodecTest.<Color>leer(b(0), r -> r.enumValue(Color.class))).isEqualTo(Color.ROJO);
        assertThat(SamCodecTest.<Color>leer(b(2), r -> r.enumValue(Color.class))).isEqualTo(Color.AZUL);
        malFormado(b(3), r -> r.enumValue(Color.class), "valor 3 fuera de rango para Color");
        malFormado(b(0xff, 0xff, 0xff, 0xff, 0x0f), r -> r.enumValue(Color.class), "valor -1 fuera de rango para Color");
    }

    @Test
    void losOpcionalesLlevanUnBooleanoDelante() {
        assertThat(escribir(w -> w.optional(Optional.of(5), SamWriter::varInt))).containsExactly(1, 5);
        assertThat(escribir(w -> w.optional(Optional.<Integer>empty(), SamWriter::varInt))).containsExactly(0);
        assertThat(SamCodecTest.<Optional<Integer>>leer(b(1, 5), r -> r.optional(SamReader::varInt))).contains(5);
        assertThat(SamCodecTest.<Optional<Integer>>leer(b(0), r -> r.optional(SamReader::varInt))).isEmpty();
        malFormado(b(7, 5), r -> r.optional(SamReader::varInt), "booleano inválido");
    }

    @Test
    void lasListasRespetanSuMaximoDeElementos() {
        assertThat(escribir(w -> w.list(List.of(1, 2), 3, SamWriter::varInt))).containsExactly(2, 1, 2);
        assertThat(SamCodecTest.<List<Integer>>leer(b(2, 1, 2), r -> r.list(3, SamReader::varInt))).containsExactly(1, 2);
        assertThat(SamCodecTest.<List<Integer>>leer(b(3, 1, 2, 3), r -> r.list(3, SamReader::varInt))).containsExactly(1, 2, 3);
        assertThat(SamCodecTest.<List<Integer>>leer(b(0), r -> r.list(3, SamReader::varInt))).isEmpty();
        malFormado(b(4, 1, 2, 3, 4), r -> r.list(3, SamReader::varInt), "largo 4 fuera de 0..3");
        malFormado(b(0xff, 0xff, 0xff, 0xff, 0x0f), r -> r.list(3, SamReader::varInt), "largo -1 fuera de 0..3");
        assertThatThrownBy(() -> escribir(w -> w.list(List.of(1, 2), 1, SamWriter::varInt)))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("largo 2 fuera de 0..1");
        assertThatThrownBy(() -> leer(b(1, 1), r -> r.list(3, SamReader::varInt)).add(9))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void losBytesSobrantesAlFinalSonMalFormados() {
        malFormado(b(1, 2), SamReader::bool, "sobran 1 bytes al final del mensaje");
        malFormado(b(5, 6, 7), SamReader::varInt, "sobran 2 bytes al final del mensaje");
    }

    @Test
    void unMensajeMasGrandeQueSuMaximoSeRechazaSinLeerlo() {
        var grande = new byte[513];
        var buf = Unpooled.wrappedBuffer(grande);
        assertThatThrownBy(() -> SamReader.decode(buf, 512, SamReader::varInt))
            .isInstanceOfSatisfying(ProtocolException.class, e -> assertThat(e.code()).isEqualTo("SAM-P001"))
            .hasMessage("mensaje de 513 bytes, máximo 512");
        assertThat(buf.readerIndex()).isZero();
        var justo = new byte[512];
        justo[0] = 0x7f;
        assertThat(SamCodecTest.<byte[]>decodificar(Unpooled.wrappedBuffer(justo), 512, r -> r.fixed(512))).hasSize(512);
    }

    @Test
    void unMensajeCompuestoVaYVuelve() {
        var bytes = escribir(w -> w.varInt(1).string("Steve", 16).optional(Optional.of(b(1, 2)), (x, v) -> x.bytes(v, 8))
            .list(List.of("a", "b"), 4, (x, v) -> x.string(v, 4)).enumValue(Color.VERDE).bool(true));
        var leido = leer(bytes, r -> List.of(r.varInt(), r.string(16), r.optional(x -> x.bytes(8)).map(v -> v.length).orElse(-1),
            r.list(4, x -> x.string(4)), r.enumValue(Color.class), r.bool()));
        assertThat(leido).containsExactly(1, "Steve", 2, List.of("a", "b"), Color.VERDE, true);
        assertThat(new String(bytes, 2, 5, StandardCharsets.UTF_8)).isEqualTo("Steve");
    }
}
