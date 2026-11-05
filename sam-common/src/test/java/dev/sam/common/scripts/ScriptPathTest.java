package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * PROTOCOLO.md 8.2: rutas de los archivos de un script. Mismas reglas que las resource locations
 * de Minecraft ([a-z0-9_.-/]), lo que además evita colisiones de mayúsculas y trucos de Unicode.
 */
class ScriptPathTest {

    @ParameterizedTest
    @ValueSource(strings = {"manifest.json", "main.lua", "ui/panel.lua", "assets/icono.png", "a-b_c.d/e", "a/b/c/d.lua", ".oculto", "a..b"})
    void aceptaRutasRelativasValidas(String ruta) {
        assertThat(ScriptPath.of(ruta).value()).isEqualTo(ruta);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",                 // vacía
        "/abs.lua",         // absoluta
        "../x.lua",         // escapa del script
        "a/../b.lua",
        "a/./b.lua",
        "./a.lua",
        ".", "..",
        "a//b.lua",         // segmento vacío
        "a/",               // termina en separador
        "Main.lua",         // mayúsculas: colisión en Windows con main.lua
        "a b.lua",          // espacio
        "a\\b.lua",         // separador de Windows
        "c:/x.lua",         // unidad de Windows
        "ñ.lua",            // no ASCII
        "a\u0000.lua",      // carácter de control
    })
    void rechazaRutasInvalidas(String ruta) {
        assertThatThrownBy(() -> ScriptPath.of(ruta))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ruta");
    }

    @Test
    void elLimiteEsDe256Caracteres() {
        var larga = "a/".repeat(127) + "ab";
        assertThat(larga).hasSize(256);
        assertThat(ScriptPath.of(larga).value()).isEqualTo(larga);
        assertThatThrownBy(() -> ScriptPath.of(larga + "c")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void elMensajeMuestraLaRutaRechazada() {
        assertThatThrownBy(() -> ScriptPath.of("../secreto.lua")).hasMessageContaining("../secreto.lua");
    }

    @Test
    void igualdadPorValorYOrdenPorBytes() {
        assertThat(ScriptPath.of("a.lua")).isEqualTo(ScriptPath.of("a.lua")).hasSameHashCodeAs(ScriptPath.of("a.lua"))
            .isNotEqualTo(ScriptPath.of("b.lua"));
        assertThat(ScriptPath.of("a-b")).isLessThan(ScriptPath.of("a.b"));
        assertThat(ScriptPath.of("a/b")).isLessThan(ScriptPath.of("a_b"));
        assertThat(ScriptPath.of("a")).isLessThan(ScriptPath.of("ab"));
        assertThat(ScriptPath.of("a.lua")).hasToString("a.lua");
    }
}
