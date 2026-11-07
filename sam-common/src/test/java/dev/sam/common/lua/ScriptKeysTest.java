package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Las teclas que eligió el jugador para los scripts ({@code script-keys.properties}, PROTOCOLO.md 8.3):
 * una línea {@code <servidor>.<script>.<id>=<tecla>} por tecla; la primera vez se agrega la del script.
 */
class ScriptKeysTest {

    @Test
    void laPrimeraVezSeUsaLaDelScriptYDespuesLaDelJugador() {
        var keys = ScriptKeys.parse("");
        assertThat(keys.choose("abcd", "tienda", "menu", "m")).isEqualTo("m");
        assertThat(keys.dirty()).isTrue();
        keys.saved();
        assertThat(keys.choose("abcd", "tienda", "menu", "k")).as("ya estaba").isEqualTo("m");
        assertThat(keys.dirty()).isFalse();
        keys.set("abcd", "tienda", "menu", "F5");
        assertThat(keys.choose("abcd", "tienda", "menu", "m")).isEqualTo("f5");
        assertThat(keys.dirty()).isTrue();
        keys.set("abcd", "tienda", "menu", "none");
        assertThat(keys.choose("abcd", "tienda", "menu", "m")).isEqualTo("none");
    }

    @Test
    void elArchivoVaYVuelveYToleraLoEscritoAMano() {
        var keys = ScriptKeys.parse("""
            # comentario
            ! también comentario
            #abcd.c.d=e
            !abcd.c.f=g
            =sin nombre

            abcd.tienda.menu = M
            abcd.tienda.raro=ctrl
            sin-igual
            """);
        assertThat(keys.choose("abcd", "tienda", "menu", "x")).isEqualTo("m");
        // Un valor que no es una tecla vale como desactivada
        assertThat(keys.choose("abcd", "tienda", "raro", "x")).isEqualTo("none");
        assertThat(keys.dirty()).isFalse();
        keys.choose("ffff", "otro", "a", "1");
        var texto = keys.text();
        assertThat(texto).startsWith("# Teclas de los scripts de servidor").contains("abcd.tienda.menu=m\n", "abcd.tienda.raro=ctrl\n",
            "ffff.otro.a=1\n");
        assertThat(texto).doesNotContain("abcd.c.", "=sin nombre");
        assertThat(keys.of("abcd")).extracting(ScriptKeys.Choice::script).containsOnly("tienda");
        assertThat(texto.indexOf("abcd.tienda.menu")).isLessThan(texto.indexOf("ffff.otro.a"));
        var vuelta = ScriptKeys.parse(texto);
        assertThat(vuelta.choose("ffff", "otro", "a", "z")).isEqualTo("1");
    }

    @Test
    void soloSeAceptanTeclasValidas() {
        for (var tecla : new String[] {"a", "z", "0", "9", "f", "f1", "f9", "f10", "f12", "none"}) {
            assertThat(ScriptKeys.valid(tecla)).as(tecla).isTrue();
        }
        for (var tecla : new String[] {"", "aa", "f0", "f13", "F1", "ctrl", "-", "f1x"}) {
            assertThat(ScriptKeys.valid(tecla)).as(tecla).isFalse();
        }
        var keys = ScriptKeys.parse("");
        assertThatThrownBy(() -> keys.set("abcd", "s", "a", "ctrl")).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("tecla desconocida \"ctrl\" (a-z, 0-9, f1-f12 o none)");
        assertThat(keys.dirty()).isFalse();
    }

    @Test
    void lasTeclasDeUnServidorSeListan() {
        var keys = ScriptKeys.parse("abcd.tienda.menu=m\nabcd.mapa.abrir=n\nffff.otro.a=1\n");
        assertThat(keys.of("abcd")).containsExactly(new ScriptKeys.Choice("mapa", "abrir", "n"), new ScriptKeys.Choice("tienda", "menu", "m"));
        assertThat(keys.of("eeee")).isEmpty();
    }
}
