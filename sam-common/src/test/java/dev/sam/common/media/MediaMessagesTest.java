package dev.sam.common.media;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.function.Consumer;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * Los mensajes de imágenes (docs/plugins/sam-mensajes.md): fragmentos de 32 KiB, hasta 256 KiB por imagen,
 * en orden; lo que no cumple es {@code SAM-P001} o {@code SAM-P002}.
 */
class MediaMessagesTest {

    private static byte[] escribir(Consumer<SamWriter> mensaje) {
        var buf = Unpooled.buffer();
        mensaje.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    private static <T> T leer(byte[] bytes, int max, Function<SamReader, T> mensaje) {
        return SamReader.decode(Unpooled.wrappedBuffer(bytes), max, mensaje);
    }

    private static byte[] id(int valor) {
        var id = new byte[16];
        Arrays.fill(id, (byte) valor);
        return id;
    }

    @Test
    void losMensajesVanYVuelven() {
        var up = new MediaMessages.Up(3, 1, 2, new byte[] {1, 2});
        assertThat(leer(escribir(up::write), MediaMessages.Up.MAX_BYTES, MediaMessages.Up::read)).usingRecursiveComparison().isEqualTo(up);
        var ready = new MediaMessages.Ready(3, id(7));
        assertThat(leer(escribir(ready::write), 64, MediaMessages.Ready::read)).usingRecursiveComparison().isEqualTo(ready);
        var get = new MediaMessages.Get(id(8));
        assertThat(leer(escribir(get::write), MediaMessages.Get.MAX_BYTES, MediaMessages.Get::read)).usingRecursiveComparison().isEqualTo(get);
        var down = new MediaMessages.Down(id(9), 0, 1, new byte[32 * 1024]);
        assertThat(leer(escribir(down::write), MediaMessages.Down.MAX_BYTES, MediaMessages.Down::read).data()).hasSize(32 * 1024);
        var failed = new MediaMessages.Failed(new byte[] {4}, "como mucho 5 imágenes por minuto");
        assertThat(leer(escribir(failed::write), 512, MediaMessages.Failed::read)).usingRecursiveComparison().isEqualTo(failed);
        assertThatThrownBy(() -> new MediaMessages.Ready(1, new byte[15])).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("el id de una imagen mide 16 bytes");
        assertThatThrownBy(() -> new MediaMessages.Get(new byte[17])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MediaMessages.Down(new byte[1], 0, 1, new byte[0])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> leer(escribir(w -> w.varInt(1).varInt(0).varInt(1).bytes(new byte[32 * 1024 + 1], 1 << 20)), 1 << 20,
            MediaMessages.Up::read)).isInstanceOf(ProtocolException.class);
        assertThatThrownBy(() -> leer(escribir(w -> w.bytes(new byte[17], 17).string("x", 128)), 512, MediaMessages.Failed::read))
            .isInstanceOf(ProtocolException.class);
        assertThat(leer(escribir(ready::write), 64, MediaMessages.Ready::read).media()).isEqualTo(id(7));
        assertThat(leer(escribir(down::write), MediaMessages.Down.MAX_BYTES, MediaMessages.Down::read).media()).isEqualTo(id(9));
        assertThat(leer(escribir(failed::write), 512, MediaMessages.Failed::read).ref()).containsExactly(4);
        // Los arreglos se copian
        var datos = new byte[] {1};
        var copia = new MediaMessages.Up(1, 0, 1, datos);
        datos[0] = 2;
        copia.data()[0] = 3;
        assertThat(copia.data()).containsExactly(1);
        var copiaId = new MediaMessages.Get(id(1));
        copiaId.media()[0] = 0;
        assertThat(copiaId.media()).isEqualTo(id(1));
    }

    @Test
    void unaImagenSeCortaYSeArma() {
        var imagen = new byte[100_000];
        new java.util.Random(1).nextBytes(imagen);
        var trozos = MediaMessages.chunks(imagen);
        assertThat(trozos).hasSize(4);
        assertThat(trozos.getFirst()).hasSize(32 * 1024);
        var armado = new MediaMessages.Assembly();
        for (var i = 0; i < trozos.size(); i++) {
            var resultado = armado.accept(i, trozos.size(), trozos.get(i));
            assertThat(resultado.isPresent()).isEqualTo(i == trozos.size() - 1);
            if (resultado.isPresent()) {
                assertThat(resultado.get()).isEqualTo(imagen);
            }
        }
        assertThat(MediaMessages.chunks(new byte[0])).singleElement().satisfies(c -> assertThat(c).isEmpty());
        assertThat(MediaMessages.chunks(new byte[64 * 1024])).hasSize(2);
    }

    @Test
    void elArmadoExigeOrdenYTope() {
        falla(a -> a.accept(1, 2, new byte[1]), "fragmento fuera de orden");
        falla(a -> a.accept(0, 0, new byte[1]), "fragmento fuera de orden");
        falla(a -> a.accept(0, 9, new byte[1]), "una imagen tiene como mucho 8 fragmentos");
        falla(a -> {
            a.accept(0, 2, new byte[1]);
            a.accept(1, 3, new byte[1]);
        }, "fragmento fuera de orden");
        falla(a -> {
            for (var i = 0; i < 8; i++) {
                a.accept(i, 8, new byte[32 * 1024 + (i == 7 ? 1 : 0)]);
            }
        }, "la imagen supera los 256 KiB");
        // Justo 256 KiB en 8 fragmentos
        var lleno = new MediaMessages.Assembly();
        for (var i = 0; i < 7; i++) {
            assertThat(lleno.accept(i, 8, new byte[32 * 1024])).isEmpty();
        }
        assertThat(lleno.accept(7, 8, new byte[32 * 1024]).orElseThrow()).hasSize(256 * 1024);
        // Después de completarse, empieza de nuevo
        assertThat(lleno.accept(0, 1, new byte[] {5}).orElseThrow()).containsExactly(5);
    }

    private static void falla(Consumer<MediaMessages.Assembly> pasos, String motivo) {
        assertThatThrownBy(() -> pasos.accept(new MediaMessages.Assembly())).isInstanceOfSatisfying(ProtocolException.class,
            e -> assertThat(e.code()).isEqualTo("SAM-P002")).hasMessage(motivo);
    }
}
