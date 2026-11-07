package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.scripts.ScriptManifest;

/**
 * {@code storage} en el servidor (RS-LUA-02b) y {@code game} en el cliente (RS-LUA-10, RN-28), PROTOCOLO.md
 * 8.3: los datos guardados son {@code LuaData} con cuota, y lo legible de la partida es una lista cerrada.
 */
class StorageAndGameTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);

    private final List<String> log = new ArrayList<>();
    private final Map<String, ScriptStore> stores = new HashMap<>();

    private ScriptHost servidor(boolean conAlmacen) {
        return new ScriptHost(new ScriptHost.Bridge() {
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
            public Optional<ScriptStore> store(String script) {
                return conAlmacen ? Optional.of(stores.computeIfAbsent(script, s -> new ScriptStore())) : Optional.empty();
            }
        }, LIMITES);
    }

    private static ScriptHost.Package script(String id, ScriptManifest.Side lado, String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest(id, "1.0", lado, List.of(), List.of(capacidades), false), Map.of("main.lua", main));
    }

    @Test
    void losDatosGuardadosSobrevivenAUnaRecarga() {
        var host = servidor(true);
        host.load(List.of(script("puntos", ScriptManifest.Side.SERVER, """
            sam.store.set("steve", {puntos = 10, nombre = "Steve"})
            sam.store.set("alex", 3)
            sam.log(tostring(sam.store.set("borrar", true)) .. "," .. tostring(sam.store.set("borrar", false)))
            sam.store.set("borrar", nil)
            sam.log(table.concat(sam.store.keys(), ","))
            """, "storage")));
        assertThat(log).containsExactly("false,true", "alex,steve");
        assertThat(stores.get("puntos").dirty()).isTrue();
        host.load(List.of(script("puntos", ScriptManifest.Side.SERVER, """
            local s = sam.store.get("steve")
            sam.log(s.nombre .. " " .. s.puntos .. " " .. sam.store.get("alex") .. " " .. tostring(sam.store.get("nada")))
            """, "storage")));
        assertThat(log).last().isEqualTo("Steve 10 3 nil");
    }

    @Test
    void loQueNoCabeEsUnErrorDelScriptYNoSeGuarda() {
        var host = servidor(true);
        var casos = Map.of(
            "sam.store.set('Mal', 1)", "clave inválida \"Mal\"",
            "sam.store.set('a', function() end)", "no se puede enviar un valor de tipo function",
            "sam.store.set('a', string.rep('x', 4000))", "los datos ocupan más de 4000 bytes",
            "for i = 1, 1025 do sam.store.set('k' .. i, 1) end", "como mucho 1024 claves por script");
        for (var caso : casos.entrySet()) {
            stores.clear();
            host.load(List.of(script("s", ScriptManifest.Side.SERVER, caso.getKey(), "storage")));
            assertThat(host.status().getFirst().state()).as(caso.getKey()).isEqualTo(ScriptHost.State.FAILED);
            assertThat(host.status().getFirst().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        // Lo que entró antes del error queda; la llamada que no cabe no guarda nada
        stores.clear();
        host.load(List.of(script("s", ScriptManifest.Side.SERVER, "for i = 1, 1025 do sam.store.set('k' .. i, 1) end", "storage")));
        assertThat(stores.get("s").keys()).hasSize(1024).doesNotContain("k1025");
    }

    @Test
    void sinAlmacenOSinCapacidadNoHayStore() {
        servidor(false).load(List.of(script("a", ScriptManifest.Side.SERVER, "sam.log(type(sam.store))", "storage")));
        servidor(true).load(List.of(script("b", ScriptManifest.Side.SERVER, "sam.log(type(sam.store))")));
        var cliente = ScriptHost.client((s, text) -> log.add(text), LIMITES);
        cliente.load(List.of(script("c", ScriptManifest.Side.CLIENT, "sam.log(type(sam.store))", "storage")));
        assertThat(log).containsExactly("nil", "nil", "nil");
        assertThat(stores).isEmpty();
    }

    private static final ScriptHost.GameState PARTIDA = new ScriptHost.GameState("Steve", 18.5, 20, 17, 10.5, 64, -3.25,
        "minecraft:overworld", List.of(new ScriptHost.Item("minecraft:stone", 32), new ScriptHost.Item("minecraft:air", 0)), 2,
        List.of("Steve", "Alex"), 3, 427, 240);

    @Test
    void elClienteLeeSoloLaListaCerradaDeDatos() {
        var estado = new java.util.concurrent.atomic.AtomicReference<Optional<ScriptHost.GameState>>(Optional.of(PARTIDA));
        var cliente = ScriptHost.client(new ScriptHost.ClientBridge() {
            @Override
            public void log(String s, String text) {
                log.add(text);
            }

            @Override
            public Optional<ScriptHost.GameState> game() {
                return estado.get();
            }
        }, LIMITES);
        cliente.load(List.of(script("g", ScriptManifest.Side.CLIENT, """
            local e = sam.game.state()
            sam.log(e.name .. " " .. e.health .. "/" .. e.max_health .. " " .. e.food)
            sam.log(e.x .. " " .. e.y .. " " .. e.z .. " " .. e.dimension)
            sam.log(e.hotbar[1].id .. " x" .. e.hotbar[1].count .. ", " .. e.hotbar[2].id .. " x" .. e.hotbar[2].count .. ", sel " .. e.selected)
            sam.log(table.concat(e.players, ",") .. " gui " .. e.gui.scale .. " " .. e.gui.width .. "x" .. e.gui.height)
            local n = 0 for k in pairs(e) do n = n + 1 end
            sam.log("campos " .. n)
            function consultar() sam.log(tostring(sam.game.state())) end
            """, "game")));
        assertThat(log).containsExactly("Steve 18.5/20 17", "10.5 64 -3.25 minecraft:overworld",
            "minecraft:stone x32, minecraft:air x0, sel 2", "Steve,Alex gui 3 427x240", "campos 12");
        estado.set(Optional.empty());
        cliente.call("g", "consultar");
        assertThat(log).last().isEqualTo("nil");
        // Sin la capacidad, o en el servidor, no existe
        cliente.load(List.of(script("n", ScriptManifest.Side.CLIENT, "sam.log(type(sam.game))")));
        servidor(true).load(List.of(script("s", ScriptManifest.Side.SERVER, "sam.log(type(sam.game))", "game")));
        assertThat(log).endsWith("nil", "nil");
        // Con el puente mínimo, fuera del mundo
        var minimo = ScriptHost.client((s, text) -> log.add(text), LIMITES);
        minimo.load(List.of(script("m", ScriptManifest.Side.CLIENT, "sam.log(tostring(sam.game.state()))", "game")));
        assertThat(log).last().isEqualTo("nil");
    }

    @Test
    void laListaDeJugadoresSeCortaEn200() {
        var muchos = new ScriptHost.GameState("Steve", 20, 20, 20, 0, 0, 0, "minecraft:the_nether", List.of(), 1,
            Collections.nCopies(250, "x"), 2, 100, 100);
        var cliente = ScriptHost.client(new ScriptHost.ClientBridge() {
            @Override
            public void log(String s, String text) {
                log.add(text);
            }

            @Override
            public Optional<ScriptHost.GameState> game() {
                return Optional.of(muchos);
            }
        }, LIMITES);
        cliente.load(List.of(script("g", ScriptManifest.Side.CLIENT, "sam.log(#sam.game.state().players .. ' ' .. #sam.game.state().hotbar)",
            "game")));
        assertThat(log).containsExactly("200 0");
    }
}
