package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.scripts.ScriptManifest;

/**
 * Los permisos desde Lua (RF-PERM-07, docs/PERMISOS.md sección 5): solo lectura, y un comando de script puede
 * exigir un nodo.
 */
class PermissionsApiTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);

    private final List<String> log = new ArrayList<>();

    private final ScriptHost host = new ScriptHost(new ScriptHost.Bridge() {
        @Override
        public List<ScriptHost.Player> players() {
            return List.of();
        }

        @Override
        public void tell(String player, String text) {
        }

        @Override
        public void broadcast(String text) {
        }

        @Override
        public void log(String script, String text) {
            log.add(text);
        }

        @Override
        public boolean has(String player, String node) {
            return player.equals("Steve") && node.equals("tienda.vip");
        }

        @Override
        public Optional<String> meta(String player, String key) {
            return player.equals("Steve") && key.equals("sam.homes.limit") ? Optional.of("5") : Optional.empty();
        }
    }, LIMITES);

    private static ScriptHost.Package script(String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest("tienda", "1", ScriptManifest.Side.SERVER, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main));
    }

    @Test
    void sinLaCapacidadNoHayConsultas() {
        host.load(List.of(script("sam.log(type(sam.has) .. ',' .. type(sam.meta))")));
        assertThat(log).containsExactly("nil,nil");
    }

    @Test
    void enElClienteNoExisteYElPuenteMinimoNoConcedeNada() {
        var cliente = ScriptHost.client((s, text) -> log.add(text), LIMITES);
        cliente.load(List.of(script("sam.log(type(sam.has) .. ',' .. type(sam.meta))", "permissions")));
        var minimo = new ScriptHost(new ScriptHost.Bridge() {
            @Override
            public List<ScriptHost.Player> players() {
                return List.of();
            }

            @Override
            public void tell(String player, String text) {
            }

            @Override
            public void broadcast(String text) {
            }

            @Override
            public void log(String script, String text) {
                log.add(text);
            }
        }, LIMITES);
        minimo.load(List.of(script("sam.log(tostring(sam.has('Steve', 'a')) .. ',' .. tostring(sam.meta('Steve', 'a')))", "permissions")));
        assertThat(log).containsExactly("nil,nil", "false,nil");
    }

    @Test
    void conLaCapacidadSeConsultanPermisosYMetas() {
        host.load(List.of(script("""
            sam.log(tostring(sam.has("Steve", "tienda.vip")) .. "," .. tostring(sam.has("Alex", "tienda.vip")))
            sam.log(tostring(sam.meta("Steve", "sam.homes.limit")) .. "," .. tostring(sam.meta("Steve", "otra")))
            """, "permissions")));
        assertThat(log).containsExactly("true,false", "5,nil");
    }

    @Test
    void unComandoPuedeExigirUnNodo() {
        host.load(List.of(script("""
            sam.command("vip", function() return "hola vip" end, {node = "tienda.vip"})
            sam.command("abierto", function() end)
            sam.command("ops", function() end, {permission = 4, node = "tienda.ops"})
            sam.command("todos", function() end, {permission = 0, node = "tienda.todos"})
            """, "commands", "permissions")));
        // Con node y sin permission, lo indefinido cae en nivel 2 (operadores), no en "todos"
        assertThat(host.commands()).containsExactly(new ScriptHost.Command("vip", 2, "tienda", Optional.of("tienda.vip")),
            new ScriptHost.Command("abierto", 0, "tienda", Optional.empty()),
            new ScriptHost.Command("ops", 4, "tienda", Optional.of("tienda.ops")),
            new ScriptHost.Command("todos", 0, "tienda", Optional.of("tienda.todos")));
        // node necesita la capacidad permissions y un nodo válido
        host.load(List.of(script("sam.command('vip', function() end, {node = 'tienda.vip'})", "commands")));
        assertThat(host.status().getFirst().errors().getFirst()).contains("node requiere la capacidad permissions");
        host.load(List.of(script("sam.command('vip', function() end, {node = 'Mal Nodo'})", "commands", "permissions")));
        assertThat(host.status().getFirst().errors().getFirst()).contains("nodo inválido \"Mal Nodo\"");
        host.load(List.of(script("sam.command('vip', function() end, {node = '" + "a".repeat(129) + "'})", "commands", "permissions")));
        assertThat(host.status().getFirst().errors().getFirst()).contains("nodo inválido");
        host.load(List.of(script("sam.command('vip', function() end, {node = '" + "a".repeat(128) + "'})", "commands", "permissions")));
        assertThat(host.status().getFirst().errors()).isEmpty();
    }

    @Test
    void unErrorDeEnlaceDeSamNoTumbaAlServidor() {
        // Una librería compilada para otra versión de Minecraft falla con NoSuchMethodError dentro de la API
        var roto = new ScriptHost(new ScriptHost.Bridge() {
            @Override
            public List<ScriptHost.Player> players() {
                throw new NoSuchMethodError("net.minecraft.class_3222.method_64396()");
            }

            @Override
            public void tell(String player, String text) {
            }

            @Override
            public void broadcast(String text) {
            }

            @Override
            public void log(String script, String text) {
                log.add(text);
            }
        }, LIMITES);
        roto.load(List.of(script("sam.log('antes') local ok = pcall(sam.players) sam.log('pcall ' .. tostring(ok)) sam.players()", "players")));
        assertThat(roto.status().getFirst().state()).isEqualTo(ScriptHost.State.FAILED);
        assertThat(roto.status().getFirst().errors().getFirst()).contains("error interno de SAM").contains("method_64396");
        assertThat(log).containsExactly("antes");
    }
}
