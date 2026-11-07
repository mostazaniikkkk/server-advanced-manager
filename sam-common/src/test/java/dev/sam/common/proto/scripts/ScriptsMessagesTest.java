package dev.sam.common.proto.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import dev.sam.common.scripts.SignedBlob;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * Los mensajes de la entrega de scripts al cliente (PROTOCOLO.md 5.5) van y vuelven por el codec estricto
 * con sus límites; lo que el cliente manda cabe en los máximos de 5.6.
 */
class ScriptsMessagesTest {

    private static byte[] escribir(Consumer<SamWriter> mensaje) {
        var buf = Unpooled.buffer();
        mensaje.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    private static <T> T leer(byte[] bytes, int max, Function<SamReader, T> mensaje) {
        return SamReader.decode(Unpooled.wrappedBuffer(bytes), max, mensaje);
    }

    private static byte[] hash(int valor) {
        var h = new byte[32];
        Arrays.fill(h, (byte) valor);
        return h;
    }

    private static void malFormado(Consumer<SamWriter> bytes, Function<SamReader, ?> mensaje, String detalle) {
        assertThatThrownBy(() -> leer(escribir(bytes), 1 << 20, mensaje))
            .isInstanceOfSatisfying(ProtocolException.class, e -> assertThat(e.code()).isEqualTo("SAM-P001"))
            .hasMessage(detalle);
    }

    private static ScriptRef ref(String id) {
        return new ScriptRef(id, "1.0.0", hash(7), 1234, true, List.of("hud", "screens"));
    }

    @Test
    void laOfertaLlevaLaKeylistYLasReferencias() {
        var keylist = new SignedBlob("keylist", 1, 99L, new byte[] {1, 2}, new byte[64]);
        var oferta = new ScriptsOffer(keylist, List.of(ref("panel"), new ScriptRef("mapa", "", hash(9), 0, false, List.of())));
        var leida = leer(escribir(oferta::write), ScriptsOffer.MAX_BYTES, ScriptsOffer::read);
        assertThat(leida).usingRecursiveComparison().isEqualTo(oferta);
        assertThat(leida.scripts().get(0).sha256()).isEqualTo(hash(7));
        // El máximo de la oferta cabe en MAX_BYTES
        var grande = new ScriptRef("a".repeat(64), "v".repeat(32), hash(1), ScriptRef.MAX_SIZE, true,
            Collections.nCopies(32, "c".repeat(48)));
        var maxima = new ScriptsOffer(new SignedBlob("k".repeat(32), Integer.MAX_VALUE, 1L, new byte[SignedBlob.MAX_BODY], new byte[64]),
            Collections.nCopies(128, grande));
        assertThat(leer(escribir(maxima::write), ScriptsOffer.MAX_BYTES, ScriptsOffer::read).scripts()).hasSize(128);
        assertThatThrownBy(() -> new ScriptsOffer(keylist, Collections.nCopies(129, ref("x")))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("largo 129 fuera de 0..128");
    }

    @Test
    void unaReferenciaInvalidaSeRechaza() {
        assertThatThrownBy(() -> new ScriptRef("x", "1", new byte[31], 0, true, List.of())).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("sha256 debe tener 32 bytes");
        assertThatThrownBy(() -> new ScriptRef("x", "1", hash(1), -1, true, List.of())).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("tamaño -1 fuera de 0..4194304");
        assertThatThrownBy(() -> new ScriptRef("x", "1", hash(1), ScriptRef.MAX_SIZE + 1, true, List.of()))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("tamaño 4194305 fuera de 0..4194304");
        malFormado(w -> w.string("x", 64).string("1", 32).fixed(hash(1), 32).varInt(-1).bool(true).list(List.of(), 32, (x, c) -> { }), ScriptRef::read, "tamaño -1 fuera de 0..4194304");
        malFormado(w -> w.string("a".repeat(65), 65), ScriptRef::read, "largo 65 fuera de 0..64");
        malFormado(w -> w.string("x", 64).string("v".repeat(33), 33), ScriptRef::read, "largo 33 fuera de 0..32");
        malFormado(w -> w.string("x", 64).string("1", 32).fixed(hash(1), 32).varInt(1).bool(true).list(List.of("c".repeat(49)), 32,
            (x, c) -> x.string(c, 49)), ScriptRef::read, "largo 49 fuera de 0..48");
        malFormado(w -> w.string("x", 64).string("1", 32).fixed(hash(1), 32).varInt(1).bool(true).list(Collections.nCopies(33, "c"), 33,
            (x, c) -> x.string(c, 48)), ScriptRef::read, "largo 33 fuera de 0..32");
        // Los arreglos se copian
        var r = ref("x");
        r.sha256()[0] = 0;
        assertThat(r.sha256()).isEqualTo(hash(7));
    }

    @Test
    void elPedidoLlevaLosHashesQueFaltan() {
        var pedido = new ScriptsWant(List.of(hash(1), hash(2)));
        var leido = leer(escribir(pedido::write), ScriptsWant.MAX_BYTES, ScriptsWant::read);
        assertThat(leido.hashes()).containsExactly(hash(1), hash(2));
        var maximo = new ScriptsWant(Collections.nCopies(128, hash(3)));
        assertThat(leer(escribir(maximo::write), ScriptsWant.MAX_BYTES, ScriptsWant::read).hashes()).hasSize(128);
        malFormado(w -> w.list(Collections.nCopies(129, hash(1)), 129, (x, h) -> x.fixed(h, 32)), ScriptsWant::read,
            "largo 129 fuera de 0..128");
        assertThatThrownBy(() -> new ScriptsWant(List.of(new byte[31]))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("sha256 debe tener 32 bytes");
        var mutable = new java.util.ArrayList<byte[]>(List.of(hash(4)));
        var copia = new ScriptsWant(mutable);
        mutable.get(0)[0] = 0;
        copia.hashes().get(0)[1] = 0;
        assertThat(copia.hashes()).containsExactly(hash(4));
    }

    @Test
    void elFragmentoLlevaSuPosicionYSusBytes() {
        var trozo = new ScriptChunk(hash(5), 2, 3, new byte[] {9, 8});
        var leido = leer(escribir(trozo::write), ScriptChunk.MAX_BYTES, ScriptChunk::read);
        assertThat(leido).usingRecursiveComparison().isEqualTo(trozo);
        var lleno = new ScriptChunk(hash(5), 0, 1, new byte[128 * 1024]);
        assertThat(leer(escribir(lleno::write), ScriptChunk.MAX_BYTES, ScriptChunk::read).data()).hasSize(128 * 1024);
        malFormado(w -> w.fixed(hash(1), 32).varInt(0).varInt(1).bytes(new byte[128 * 1024 + 1], 1 << 20), ScriptChunk::read,
            "largo 131073 fuera de 0..131072");
        assertThatThrownBy(() -> new ScriptChunk(new byte[33], 0, 1, new byte[0])).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("sha256 debe tener 32 bytes");
        var datos = new byte[] {1};
        var copia = new ScriptChunk(hash(1), 0, 1, datos);
        datos[0] = 2;
        copia.data()[0] = 3;
        copia.sha256()[0] = 0;
        assertThat(copia.data()).containsExactly(1);
        assertThat(copia.sha256()).isEqualTo(hash(1));
    }

    @Test
    void elConsentimientoLlevaLosIdsAceptados() {
        var si = new ScriptsConsent(List.of("panel", "mapa"));
        assertThat(leer(escribir(si::write), ScriptsConsent.MAX_BYTES, ScriptsConsent::read)).isEqualTo(si);
        var maximo = new ScriptsConsent(Collections.nCopies(128, "a".repeat(64)));
        assertThat(leer(escribir(maximo::write), ScriptsConsent.MAX_BYTES, ScriptsConsent::read)).isEqualTo(maximo);
        malFormado(w -> w.list(List.of("a".repeat(65)), 128, (x, s) -> x.string(s, 65)), ScriptsConsent::read, "largo 65 fuera de 0..64");
        malFormado(w -> w.list(Collections.nCopies(129, "a"), 129, (x, s) -> x.string(s, 64)), ScriptsConsent::read,
            "largo 129 fuera de 0..128");
        assertThat(ScriptsWant.MAX_BYTES).isLessThanOrEqualTo(4608);
        assertThat(ScriptsConsent.MAX_BYTES).isLessThanOrEqualTo(8704);
    }
}
