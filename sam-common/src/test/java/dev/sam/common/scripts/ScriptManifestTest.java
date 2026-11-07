package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

/** El manifest de un script (RF-LUA-01, PROTOCOLO.md 8.3): lectura estricta y reglas de cada campo. */
class ScriptManifestTest {

    private static ScriptManifest leer(String json) {
        return ScriptManifest.parse("economia", json.getBytes(StandardCharsets.UTF_8));
    }

    private static void invalido(String json, String motivo) {
        assertThatThrownBy(() -> leer(json)).isInstanceOf(IllegalArgumentException.class).hasMessage("manifest.json inválido: " + motivo);
    }

    @Test
    void unManifestCompletoSeLee() {
        var m = leer("""
            {"id": "economia", "version": "1.0.0", "side": "both", "dependencies": ["base", "util_2"],
             "capabilities": ["events", "provide:sam:economy"], "required": true}""");
        assertThat(m).isEqualTo(new ScriptManifest("economia", "1.0.0", ScriptManifest.Side.BOTH, List.of("base", "util_2"),
            List.of("events", "provide:sam:economy"), true));
        assertThat(m.has("events")).isTrue();
        assertThat(m.has("chat")).isFalse();
        assertThat(m.runsOnServer()).isTrue();
        assertThat(m.runsOnClient()).isTrue();
    }

    @Test
    void lasListasYRequiredSonOpcionales() {
        var m = leer("{\"id\":\"economia\",\"version\":\"0.1\",\"side\":\"server\"}");
        assertThat(m.dependencies()).isEmpty();
        assertThat(m.capabilities()).isEmpty();
        assertThat(m.required()).isFalse();
        assertThat(m.runsOnServer()).isTrue();
        assertThat(m.runsOnClient()).isFalse();
        var cliente = leer("{\"id\":\"economia\",\"version\":\"0.1\",\"side\":\"client\"}");
        assertThat(cliente.runsOnServer()).isFalse();
        assertThat(cliente.runsOnClient()).isTrue();
    }

    @Test
    void cadaReglaSeExige() {
        invalido("{\"id\":\"otro\",\"version\":\"1\",\"side\":\"server\"}", "el id \"otro\" no coincide con la carpeta \"economia\"");
        invalido("{\"version\":\"1\",\"side\":\"server\"}", "faltan id, version o side");
        invalido("{\"id\":\"economia\",\"version\":\"\",\"side\":\"server\"}", "version debe tener 1 a 32 caracteres imprimibles");
        invalido("{\"id\":\"economia\",\"version\":\"" + "1".repeat(33) + "\",\"side\":\"server\"}",
            "version debe tener 1 a 32 caracteres imprimibles");
        invalido("{\"id\":\"economia\",\"version\":\"ñ\",\"side\":\"server\"}", "version debe tener 1 a 32 caracteres imprimibles");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"web\"}", "side debe ser server, client o both");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"dependencies\":[\"Mal\"]}", "dependencia inválida \"Mal\"");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"dependencies\":[\"economia\"]}",
            "un script no puede depender de sí mismo");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":[\"ev ents\"]}", "capacidad inválida \"ev ents\"");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":[\"chat\",\"chat\"]}", "capacidad repetida \"chat\"");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"dependencies\":[\"a\",\"a\"]}", "dependencia repetida \"a\"");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":["
            + "\"c\",".repeat(32) + "\"x\"]}", "como mucho 32 capacidades");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"dependencies\":["
            + "\"d\",".repeat(16) + "\"x\"]}", "como mucho 16 dependencias");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":[\"" + "a".repeat(49) + "\"]}",
            "capacidad inválida \"" + "a".repeat(49) + "\"");
    }

    @Test
    void losTopesSeAceptanJustoEnElBorde() {
        var caps = new StringBuilder();
        for (var i = 0; i < 32; i++) {
            caps.append(i == 0 ? "" : ",").append("\"c").append(i).append("\"");
        }
        var deps = new StringBuilder();
        for (var i = 0; i < 16; i++) {
            deps.append(i == 0 ? "" : ",").append("\"d").append(i).append("\"");
        }
        var m = leer("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":[" + caps
            + "],\"dependencies\":[" + deps + "]}");
        assertThat(m.capabilities()).hasSize(32);
        assertThat(m.dependencies()).hasSize(16);
        var base = "{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\"}";
        var justo = base + " ".repeat(4096 - base.length());
        assertThat(ScriptManifest.parse("economia", justo.getBytes(StandardCharsets.UTF_8)).id()).isEqualTo("economia");
        assertThatThrownBy(() -> ScriptManifest.parse("economia", (justo + " ").getBytes(StandardCharsets.UTF_8)))
            .hasMessage("manifest.json inválido: supera los 4096 bytes");
    }

    @Test
    void laLecturaEsEstricta() {
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"extra\":1}", "campo desconocido \"extra\"");
        invalido("{\"id\":\"economia\",\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\"}", "campo repetido \"id\"");
        invalido("{\"id\":\"economia\",\"version\":1,\"side\":\"server\"}", "version debe ser texto");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"required\":\"si\"}", "required debe ser true o false");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":\"chat\"}", "capabilities debe ser una lista de textos");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":[1]}", "capabilities debe ser una lista de textos");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\"} x", "no es un objeto JSON válido");
        invalido("[]", "no es un objeto JSON válido");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",}", "no es un objeto JSON válido");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\",\"capabilities\":[\"" + "a".repeat(4096) + "\"]}",
            "supera los 4096 bytes");
        assertThat(leer(" {\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\"}\n").id()).isEqualTo("economia");
        invalido("{\"id\":\"economia\",\"version\":\"1\",\"side\":\"server\"}{}", "no es un objeto JSON válido");
        invalido("{\"id\":\"economia\",\"side\":\"server\"}", "faltan id, version o side");
        invalido("{\"id\":\"economia\",\"version\":\"1\"}", "faltan id, version o side");
    }
}
