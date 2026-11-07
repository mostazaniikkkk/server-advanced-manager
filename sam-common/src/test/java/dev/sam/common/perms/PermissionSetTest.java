package dev.sam.common.perms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.perms.PermissionSet.Value;

/**
 * Los permisos nativos de SAM (RF-PERM, docs/PERMISOS.md): grupos con peso y herencia, comodines,
 * negación, metas, vencimientos y nodos que exigen sesión verificada, con una resolución determinista.
 */
class PermissionSetTest {

    private static final long AHORA = 1_762_500_000L;

    private static final String EJEMPLO = """
        {
          "version": 1,
          "groups": {
            "default": {
              "weight": 0,
              "permissions": { "sam.command.home": true, "sam.command.spawn": true },
              "meta": { "sam.homes.limit": "1" }
            },
            "vip": {
              "weight": 10,
              "parents": ["default"],
              "permissions": { "sam.command.fly": true, "sam.command.fly.others": false, "sam.command.*": true },
              "meta": { "sam.homes.limit": "5", "sam.chat.prefix": "[VIP]" }
            },
            "moderador": {
              "weight": 50,
              "parents": ["vip"],
              "permissions": { "sam.command.home": false, "sam.mod.*": { "value": true, "verified": true } }
            },
            "admin": {
              "weight": 100,
              "parents": ["moderador"],
              "permissions": { "*": { "value": true, "verified": true } }
            }
          },
          "users": {
            "steve": {
              "groups": { "vip": {} },
              "permissions": { "sam.command.nick": { "value": true, "expires": 1765000000 }, "sam.command.fly": false },
              "meta": { "sam.homes.limit": "8" }
            },
            "alex": { "groups": { "moderador": {}, "vip": { "expires": 1762400000 } } },
            "notch": { "groups": { "admin": {} } }
          }
        }
        """;

    private static PermissionSet ejemplo() {
        return PermissionSet.parse(EJEMPLO);
    }

    @Test
    void elJugadorGanaASusGruposYElGrupoDeMasPesoAlResto() {
        var set = ejemplo();
        // El propio jugador niega fly aunque su grupo vip lo da
        assertThat(set.check("Steve", "sam.command.fly", AHORA, false))
            .isEqualTo(new PermissionSet.Check(Value.FALSE, Optional.of("jugador"), Optional.of("sam.command.fly")));
        // moderador (50) niega home aunque default lo da
        assertThat(set.check("alex", "sam.command.home", AHORA, false))
            .isEqualTo(new PermissionSet.Check(Value.FALSE, Optional.of("grupo moderador"), Optional.of("sam.command.home")));
        // Un jugador sin entrada en el archivo tiene default
        assertThat(set.check("herobrine", "sam.command.spawn", AHORA, false).value()).isEqualTo(Value.TRUE);
        assertThat(set.check("herobrine", "sam.command.fly", AHORA, false))
            .isEqualTo(new PermissionSet.Check(Value.UNDEFINED, Optional.empty(), Optional.empty()));
    }

    @Test
    void enCadaFuenteGanaLoMasEspecifico() {
        var set = ejemplo();
        // vip: sam.command.fly.others = false gana a sam.command.* = true
        assertThat(set.check("alex", "sam.command.fly.others", AHORA, false))
            .isEqualTo(new PermissionSet.Check(Value.FALSE, Optional.of("grupo vip"), Optional.of("sam.command.fly.others")));
        // y sam.command.* cubre lo que no está escrito
        assertThat(set.check("alex", "sam.command.warp", AHORA, false))
            .isEqualTo(new PermissionSet.Check(Value.TRUE, Optional.of("grupo vip"), Optional.of("sam.command.*")));
        // Un comodín no se aplica a su propio prefijo
        assertThat(set.check("alex", "sam.command", AHORA, false).value()).isEqualTo(Value.UNDEFINED);
    }

    @Test
    void loQueExigeVerificacionSoloValeConSesionVerificada() {
        var set = ejemplo();
        assertThat(set.check("notch", "minecraft.command.op", AHORA, false).value()).isEqualTo(Value.UNDEFINED);
        assertThat(set.check("notch", "minecraft.command.op", AHORA, true))
            .isEqualTo(new PermissionSet.Check(Value.TRUE, Optional.of("grupo admin"), Optional.of("*")));
        assertThat(set.check("alex", "sam.mod.mute", AHORA, false).value()).isEqualTo(Value.UNDEFINED);
        assertThat(set.check("alex", "sam.mod.mute", AHORA, true).value()).isEqualTo(Value.TRUE);
        // Sin verificar, notch igual tiene lo heredado que no lo exige
        assertThat(set.check("notch", "sam.command.fly", AHORA, false).value()).isEqualTo(Value.TRUE);
    }

    @Test
    void loVencidoNoValeYSeQuitaConSuRegistro() {
        var set = ejemplo();
        assertThat(set.check("steve", "sam.command.nick", 1_764_999_999L, false).value()).isEqualTo(Value.TRUE);
        // Al vencer el suyo, decide la siguiente fuente: el comodín de su grupo vip
        assertThat(set.check("steve", "sam.command.nick", 1_765_000_000L, false))
            .isEqualTo(new PermissionSet.Check(Value.TRUE, Optional.of("grupo vip"), Optional.of("sam.command.*")));
        assertThat(set.check("steve", "sam.command.nick", 1_764_999_999L, false).source()).contains("jugador");
        // La pertenencia de alex a vip ya venció, pero moderador hereda de vip
        assertThat(set.check("alex", "sam.command.warp", AHORA, false).value()).isEqualTo(Value.TRUE);
        var limpio = set.expire(1_765_000_000L);
        assertThat(limpio.removed()).containsExactly("alex: grupo vip", "steve: sam.command.nick");
        assertThat(limpio.set().users().get("steve").permissions()).containsOnlyKeys("sam.command.fly");
        assertThat(limpio.set().users().get("alex").groups()).containsOnlyKeys("moderador");
        assertThat(set.expire(AHORA - 200_000).removed()).isEmpty();
        // Una meta temporal
        var meta = PermissionSet.parse("""
            {"version": 1, "groups": {"default": {"meta": {"a.b": {"value": "x", "expires": 100}}}}, "users": {}}""");
        assertThat(meta.meta("cualquiera", "a.b", 99)).contains("x");
        assertThat(meta.meta("cualquiera", "a.b", 100)).isEmpty();
        assertThat(meta.expire(100).removed()).containsExactly("grupo default: meta a.b");
    }

    @Test
    void lasMetasSeResuelvenIgual() {
        var set = ejemplo();
        assertThat(set.meta("steve", "sam.homes.limit", AHORA)).contains("8");
        assertThat(set.meta("alex", "sam.homes.limit", AHORA)).contains("5");
        assertThat(set.meta("alex", "sam.chat.prefix", AHORA)).contains("[VIP]");
        assertThat(set.meta("nadie", "sam.homes.limit", AHORA)).contains("1");
        assertThat(set.meta("nadie", "sam.chat.prefix", AHORA)).isEmpty();
    }

    @Test
    void vaYVuelveDelArchivoOrdenadoYEstable() {
        var set = ejemplo();
        var json = set.toJson();
        var otra = PermissionSet.parse(json);
        assertThat(otra).isEqualTo(set);
        assertThat(otra.toJson()).isEqualTo(json);
        // Ordenado: los grupos por nombre
        assertThat(json.indexOf("\"admin\"")).isLessThan(json.indexOf("\"default\""));
        assertThat(json).startsWith("{\n  \"version\": 1,\n  \"groups\": {\n");
        // Sin archivo hay un default vacío
        assertThat(PermissionSet.empty().groups()).containsOnlyKeys("default");
        assertThat(PermissionSet.parse("{\"version\": 1}").groups()).containsOnlyKeys("default");
        assertThat(PermissionSet.parse(PermissionSet.empty().toJson())).isEqualTo(PermissionSet.empty());
    }

    @Test
    void elArchivoSeLeeEstricto() {
        invalido("{\"version\": 2}", "version debe ser 1");
        invalido("{}", "version debe ser 1");
        invalido("{\"version\": 1, \"otro\": 1}", "campo desconocido \"otro\"");
        invalido("{\"version\": 1, \"version\": 1}", "campo repetido \"version\"");
        invalido("{\"version\": 1} x", "no es JSON válido");
        invalido("{\"version\": 1, \"groups\": {\"Mal\": {}}}", "nombre de grupo inválido \"Mal\"");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"weight\": \"1\"}}}", "weight debe ser un entero");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"weight\": 1.5}}}", "weight debe ser un entero");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"parents\": [\"b\"]}}}", "el grupo a hereda de b, que no existe");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"parents\": [\"b\"]}, \"b\": {\"parents\": [\"a\"]}}}", "herencia circular en a");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"parents\": [\"a\"]}}}", "herencia circular en a");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"Sam.X\": true}}}}", "nodo inválido \"Sam.X\"");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"a.*.b\": true}}}}", "nodo inválido \"a.*.b\"");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"a\": \"si\"}}}}", "a: el valor debe ser true, false o un objeto");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"a\": {\"expires\": 5}}}}}", "a: falta value");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"a\": {\"value\": true, \"x\": 1}}}}}", "campo desconocido \"x\"");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"meta\": {\"a.*\": \"1\"}}}}", "meta inválida \"a.*\"");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"meta\": {\"a\": \"" + "x".repeat(257) + "\"}}}}", "la meta a supera los 256 caracteres");
        invalido("{\"version\": 1, \"users\": {\"Steve\": {}}}", "nick inválido \"Steve\" (en minúsculas)");
        invalido("{\"version\": 1, \"users\": {\"steve\": {\"groups\": {\"vip\": {}}}}}", "steve está en el grupo vip, que no existe");
        invalido("{\"version\": 1, \"users\": {\"steve\": {\"groups\": {\"default\": {\"x\": 1}}}}}", "campo desconocido \"x\"");
    }

    @Test
    void losTopesSeExigen() {
        var grupos = new StringBuilder("{\"version\": 1, \"groups\": {");
        for (var i = 0; i < 257; i++) {
            grupos.append(i == 0 ? "" : ",").append("\"g").append(i).append("\": {}");
        }
        invalido(grupos + "}}", "como mucho 256 grupos");
        var nodos = new StringBuilder("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {");
        for (var i = 0; i < 1025; i++) {
            nodos.append(i == 0 ? "" : ",").append("\"n").append(i).append("\": true");
        }
        invalido(nodos + "}}}}", "como mucho 1024 nodos");
        var padres = new StringBuilder("{\"version\": 1, \"groups\": {\"h\": {\"parents\": [");
        for (var i = 0; i < 17; i++) {
            padres.append(i == 0 ? "" : ",").append("\"p").append(i).append('"');
        }
        invalido(padres + "]}}}", "como mucho 16 padres");
        invalido("{\"version\": 1, \"groups\": {\"a\": {\"permissions\": {\"" + "a".repeat(129) + "\": true}}}}", "nodo inválido");
        invalido(" ".repeat(1024 * 1024) + "{\"version\": 1}", "supera 1 MiB");
    }

    private static void invalido(String json, String motivo) {
        assertThatThrownBy(() -> PermissionSet.parse(json)).isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("permissions.json inválido: ").hasMessageContaining(motivo);
    }
}
