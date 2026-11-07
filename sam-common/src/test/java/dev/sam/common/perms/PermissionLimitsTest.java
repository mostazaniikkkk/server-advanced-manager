package dev.sam.common.perms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

import org.junit.jupiter.api.Test;

import dev.sam.common.perms.PermissionSet.Value;

/** Los bordes del archivo de permisos y de la resolución (docs/PERMISOS.md, secciones 2 y 3). */
class PermissionLimitsTest {

    private static String lista(String formato, int desde, int hasta, String separador) {
        var out = new StringBuilder();
        for (var i = desde; i < hasta; i++) {
            out.append(i == desde ? "" : separador).append(formato.replace("#", String.valueOf(i)));
        }
        return out.toString();
    }

    private static void invalido(String json, String motivo) {
        assertThatThrownBy(() -> PermissionSet.parse(json)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining(motivo);
    }

    @Test
    void losTopesJustosValen() {
        var grupos = "{\"version\": 1, \"groups\": {" + lista("\"g#\": {}", 0, 256, ",") + "}}";
        assertThat(PermissionSet.parse(grupos).groups()).hasSize(257).containsKey("default");
        var padres = "{\"version\": 1, \"groups\": {" + lista("\"p#\": {}", 0, 16, ",") + ", \"h\": {\"parents\": ["
            + lista("\"p#\"", 0, 16, ",") + "]}}}";
        assertThat(PermissionSet.parse(padres).groups().get("h").parents()).hasSize(16);
        var nodos = "{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {" + lista("\"n#\": true", 0, 1024, ",") + "}}}}";
        assertThat(PermissionSet.parse(nodos).groups().get("a").permissions()).hasSize(1024);
        var metas = "{\"version\": 1, \"groups\": {\"a\": {\"meta\": {" + lista("\"m#\": \"x\"", 0, 256, ",") + "}}}}";
        assertThat(PermissionSet.parse(metas).groups().get("a").meta()).hasSize(256);
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"meta\": {" + lista("\"m#\": \"x\"", 0, 257, ",") + "}}}}", "como mucho 256 metas");
        var largos = "{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"" + "n".repeat(128) + "\": true}, \"meta\": {\""
            + "m".repeat(128) + "\": \"" + "v".repeat(256) + "\"}}}}";
        assertThat(PermissionSet.parse(largos).groups().get("a").meta()).containsKey("m".repeat(128));
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"meta\": {\"" + "m".repeat(129) + "\": \"x\"}}}}", "meta inválida");
        // Justo 1 MiB
        var base = "{\"version\": 1}";
        assertThat(PermissionSet.parse(" ".repeat(1024 * 1024 - base.length()) + base).groups()).containsOnlyKeys("default");
        // Rango de los enteros
        assertThat(PermissionSet.parse("{\"version\": 1, \"groups\": {\"a\": {\"weight\": 2147483647}, \"b\": {\"weight\": -2147483648}}}")
            .groups().get("b").weight()).isEqualTo(Integer.MIN_VALUE);
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"weight\": 2147483648}}}", "weight fuera de rango");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"weight\": -2147483649}}}", "weight fuera de rango");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"x\": {\"value\": true, \"expires\": -1}}}}}", "expires fuera de rango");
        assertThat(PermissionSet.parse("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"x\": {\"value\": true, \"expires\": 0}}}}}")
            .groups().get("a").permissions().get("x").expires()).hasValue(0);
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"weight\": 1e3}}}", "weight debe ser un entero");
    }

    @Test
    void losTiposSeExigenEnTodosLados() {
        invalido("{\"version\": 1, \"groups\": []}", "groups debe ser un objeto");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"otro\": 1}}}", "campo desconocido \"otro\"");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"parents\": \"b\"}}}", "parents debe ser una lista de grupos");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"parents\": [1]}}}", "parents debe ser una lista de grupos");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"parents\": [\"Mal\"]}}}", "parents debe ser una lista de grupos");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"x\": {\"value\": true, \"verified\": \"si\"}}}}}",
            "x: verified debe ser true o false");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"meta\": {\"m\": 5}}}}", "m: el valor debe ser un texto o un objeto");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"meta\": {\"m\": {\"value\": \"x\", \"otro\": 1}}}}}", "campo desconocido \"otro\"");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"meta\": {\"m\": {\"expires\": 1}}}}}", "m: falta value");
        invalido("{\"version\": 1, \"users\": {\"steve\": {\"otro\": 1}}}", "campo desconocido \"otro\"");
        invalido("{\"version\": 1", "no es JSON válido");
        invalido("{\"version\": 1} {}", "no es JSON válido");
        invalido("[1]", "el archivo debe ser un objeto");
        invalido("null", "no es JSON válido");
    }

    @Test
    void elArchivoEscritoEsSimpleCuandoPuede() {
        var set = PermissionSet.parse("""
            {"version": 1, "groups": {"default": {
              "permissions": {"a": true, "b": {"value": false, "expires": 5}, "c": {"value": true, "verified": true}},
              "meta": {"p": "<VIP> & =", "q": {"value": "x", "expires": 7}}}}}""");
        var json = set.toJson();
        assertThat(json).contains("\"a\": true", "\"p\": \"<VIP> & =\"", "\"b\": {\n", "\"c\": {\n", "\"q\": {\n", "\"verified\": true")
            .doesNotContain("\"verified\": false");
        assertThat(PermissionSet.parse(json)).isEqualTo(set);
    }

    @Test
    void aIgualPesoDecideElNombreYUnaPertenenciaVencidaNoCuenta() {
        var set = PermissionSet.parse("""
            {"version": 1, "groups": {"b": {"weight": 5, "permissions": {"x": false}}, "a": {"weight": 5, "permissions": {"x": true}}},
             "users": {"steve": {"groups": {"a": {}, "b": {}}}, "alex": {"groups": {"a": {"expires": 10}}}}}""");
        assertThat(set.check("steve", "x", 0, false).source()).contains("grupo a");
        assertThat(set.check("alex", "x", 9, false).value()).isEqualTo(Value.TRUE);
        assertThat(set.check("alex", "x", 10, false).value()).isEqualTo(Value.UNDEFINED);
        // El grupo directo (z) se recorre antes que el heredado (a), pero a igual peso decide el nombre
        var herencia = PermissionSet.parse("""
            {"version": 1, "groups": {"a": {"weight": 5, "permissions": {"x": true}},
             "z": {"weight": 5, "parents": ["a"], "permissions": {"x": false}}}, "users": {"steve": {"groups": {"z": {}}}}}""");
        assertThat(herencia.check("steve", "x", 0, false).source()).contains("grupo a");
        // El comodín intermedio también es candidato
        var comodines = PermissionSet.parse("{\"version\": 1, \"groups\": {\"default\": {\"permissions\": {\"a.*\": true}}}}");
        assertThat(comodines.check("x", "a.b.c", 0, false).entry()).contains("a.*");
    }

    @Test
    void unaHerenciaEnDiamanteNoSeRepiteYUnCicloArmadoEnCodigoNoCuelga() {
        var vacio = new PermissionSet.Group(0, List.of(), Map.of(), Map.of());
        var conCiclo = new PermissionSet(Map.of("default", new PermissionSet.Group(0, List.of("a"), Map.of(), Map.of()),
            "a", new PermissionSet.Group(1, List.of("default"), Map.of("x", new PermissionSet.Grant(true, OptionalLong.empty(), false)),
                Map.of())), Map.of());
        assertThat(conCiclo.check("steve", "x", 0, false).value()).isEqualTo(Value.TRUE);
        assertThat(new PermissionSet(Map.of("default", vacio), Map.of()).meta("x", "y", 0)).isEqualTo(Optional.empty());
    }
}
