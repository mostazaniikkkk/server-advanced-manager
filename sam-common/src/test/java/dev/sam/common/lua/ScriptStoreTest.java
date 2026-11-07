package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.ProtocolException;

/**
 * El almacenamiento clave-valor de un script (RS-LUA-02b, {@code storage} en PROTOCOLO.md 8.3): cuota de
 * claves y de bytes, y un formato estricto para el archivo que guarda SAM.
 */
class ScriptStoreTest {

    @Test
    void guardaLeeBorraYListaEnOrden() {
        var store = new ScriptStore();
        assertThat(store.dirty()).isFalse();
        store.set("b", Optional.of(new byte[] {2}));
        store.set("a:1", Optional.of(new byte[] {1, 1}));
        assertThat(store.dirty()).isTrue();
        assertThat(store.get("b")).contains(new byte[] {2});
        assertThat(store.get("z")).isEmpty();
        assertThat(store.keys()).containsExactly("a:1", "b");
        assertThat(store.used()).isEqualTo(1 + 1 + 3 + 2);
        store.set("b", Optional.empty());
        assertThat(store.keys()).containsExactly("a:1");
        assertThat(store.used()).isEqualTo(5);
        store.saved();
        store.set("no", Optional.empty());
        assertThat(store.dirty()).as("borrar lo que no está no cambia nada").isFalse();
        // Lo devuelto es una copia
        store.get("a:1").orElseThrow()[0] = 9;
        assertThat(store.get("a:1")).contains(new byte[] {1, 1});
    }

    @Test
    void vaYVuelveDelArchivo() {
        var store = new ScriptStore();
        store.set("puntos:steve", Optional.of(new byte[] {3, 0x40, 0x24, 0, 0, 0, 0, 0, 0}));
        store.set("puntos:alex", Optional.of(new byte[] {1}));
        var leido = ScriptStore.decode(store.encode());
        assertThat(leido.keys()).containsExactly("puntos:alex", "puntos:steve");
        assertThat(leido.get("puntos:steve")).contains(new byte[] {3, 0x40, 0x24, 0, 0, 0, 0, 0, 0});
        assertThat(leido.dirty()).isFalse();
        assertThat(leido.used()).isEqualTo(store.used());
        assertThat(ScriptStore.decode(new ScriptStore().encode()).keys()).isEmpty();
    }

    @Test
    void lasReglasSeExigen() {
        var store = new ScriptStore();
        assertThatThrownBy(() -> store.set("Mayúscula", Optional.of(new byte[1]))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("clave inválida \"Mayúscula\": [a-z0-9_.:-], hasta 64");
        assertThatThrownBy(() -> store.set("a".repeat(65), Optional.of(new byte[1]))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.set("", Optional.of(new byte[1]))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.set("a", Optional.of(new byte[4001]))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("el valor supera los 4000 bytes");
        store.set("a".repeat(64), Optional.of(new byte[4000]));
        // Cuota de claves
        var muchas = new ScriptStore();
        for (var i = 0; i < 1024; i++) {
            muchas.set("k" + i, Optional.of(new byte[0]));
        }
        assertThatThrownBy(() -> muchas.set("otra", Optional.of(new byte[0]))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("como mucho 1024 claves por script");
        muchas.set("k0", Optional.of(new byte[1]));
        // Cuota de bytes: 256 KiB entre claves y valores; reemplazar cuenta solo la diferencia.
        // 64 × (4 + 4000) + (2 + 3998) + (2 + 1886) = 262 144
        var llena = new ScriptStore();
        for (var i = 0; i < 64; i++) {
            llena.set(String.format("c%03d", i), Optional.of(new byte[4000]));
        }
        llena.set("f1", Optional.of(new byte[3998]));
        llena.set("f2", Optional.of(new byte[1886]));
        assertThat(llena.used()).isEqualTo(256 * 1024);
        assertThatThrownBy(() -> llena.set("x", Optional.of(new byte[0]))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("el script supera los 256 KiB de datos guardados");
        assertThat(llena.keys()).hasSize(66);
        llena.set("c000", Optional.of(new byte[4000]));
        assertThatThrownBy(() -> llena.set("f2", Optional.of(new byte[1887]))).isInstanceOf(IllegalArgumentException.class);
        assertThat(llena.get("f2").orElseThrow()).hasSize(1886);
        llena.set("f2", Optional.of(new byte[1885]));
        llena.set("y", Optional.of(new byte[0]));
        assertThat(llena.used()).isEqualTo(256 * 1024);
    }

    @Test
    void unArchivoInvalidoSeRechaza() {
        assertThatThrownBy(() -> ScriptStore.decode(new byte[] {1, 1, 'A', 0})).isInstanceOf(ProtocolException.class)
            .hasMessageContaining("clave inválida");
        assertThatThrownBy(() -> ScriptStore.decode(new byte[] {2, 1, 'b', 0, 1, 'a', 0})).isInstanceOf(ProtocolException.class)
            .hasMessage("claves desordenadas o repetidas");
        assertThatThrownBy(() -> ScriptStore.decode(new byte[] {2, 1, 'a', 0, 1, 'a', 0})).isInstanceOf(ProtocolException.class);
        assertThatThrownBy(() -> ScriptStore.decode(new byte[] {1, 1, 'a'})).isInstanceOf(ProtocolException.class);
    }
}
