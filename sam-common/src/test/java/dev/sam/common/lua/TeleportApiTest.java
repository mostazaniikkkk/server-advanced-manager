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
 * Posición y teletransporte desde un script de servidor (capacidad {@code teleport}, PROTOCOLO.md 8.3): la
 * acción de juego que necesitan plugins como homes y warps; coordenadas validadas.
 */
class TeleportApiTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);

    private final List<String> log = new ArrayList<>();
    private final List<ScriptHost.Position> viajes = new ArrayList<>();

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
        public Optional<ScriptHost.Position> position(String player) {
            return player.equals("Steve") ? Optional.of(new ScriptHost.Position(10.5, 64, -3.25, 90, -10, "minecraft:overworld", 18.5))
                : Optional.empty();
        }

        @Override
        public boolean teleport(String player, ScriptHost.Position to) {
            viajes.add(to);
            return player.equals("Steve") && !to.dimension().equals("minecraft:no_existe");
        }
    }, LIMITES);

    private static ScriptHost.Package script(String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest("homes", "1", ScriptManifest.Side.SERVER, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main));
    }

    @Test
    void laPosicionEsUnaCopiaYElViajeLlegaAlJuego() {
        host.load(List.of(script("""
            local p = sam.position("Steve")
            sam.log(p.x .. " " .. p.y .. " " .. p.z .. " " .. p.yaw .. " " .. p.pitch .. " " .. p.dimension .. " " .. p.health)
            sam.log(tostring(sam.position("Alex")))
            sam.log(tostring(sam.teleport("Steve", {x = 1, y = 70, z = 2, dimension = "minecraft:the_nether", yaw = 45, pitch = 5})))
            sam.log(tostring(sam.teleport("Steve", p)))
            sam.log(tostring(sam.teleport("Alex", {x = 0, y = 0, z = 0, dimension = "minecraft:overworld"})))
            sam.log(tostring(sam.teleport("Steve", {x = 0, y = 0, z = 0, dimension = "minecraft:no_existe"})))
            """, "teleport")));
        assertThat(log).containsExactly("10.5 64 -3.25 90 -10 minecraft:overworld 18.5", "nil", "true", "true", "false", "false");
        assertThat(viajes.getFirst()).isEqualTo(new ScriptHost.Position(1, 70, 2, 45, 5, "minecraft:the_nether", 0));
        assertThat(viajes.get(1)).isEqualTo(new ScriptHost.Position(10.5, 64, -3.25, 90, -10, "minecraft:overworld", 0));
        // yaw y pitch son opcionales
        host.load(List.of(script("sam.teleport('Steve', {x = 1, y = 2, z = 3, dimension = 'minecraft:overworld'})", "teleport")));
        assertThat(viajes.getLast()).isEqualTo(new ScriptHost.Position(1, 2, 3, 0, 0, "minecraft:overworld", 0));
    }

    @Test
    void lasCoordenadasSeValidan() {
        var casos = Map.of(
            "sam.teleport('Steve', {x = 30000001, y = 0, z = 0, dimension = 'minecraft:overworld'})", "x y z deben estar dentro del mundo",
            "sam.teleport('Steve', {x = 0, y = 0, z = -30000001, dimension = 'minecraft:overworld'})", "x y z deben estar dentro del mundo",
            "sam.teleport('Steve', {x = 0, y = 4097, z = 0, dimension = 'minecraft:overworld'})", "x y z deben estar dentro del mundo",
            "sam.teleport('Steve', {x = 0, y = -4097, z = 0, dimension = 'minecraft:overworld'})", "x y z deben estar dentro del mundo",
            "sam.teleport('Steve', {x = 0/0, y = 0, z = 0, dimension = 'minecraft:overworld'})", "x y z deben estar dentro del mundo",
            "sam.teleport('Steve', {x = 0, y = 0, z = 0, dimension = 'Nether'})", "dimensión inválida \"Nether\"",
            "sam.teleport('Steve', {x = 0, y = 0, z = 0})", "dimensión inválida \"nil\"");
        for (var caso : casos.entrySet()) {
            host.load(List.of(script(caso.getKey(), "teleport")));
            assertThat(host.status().getFirst().errors()).as(caso.getKey()).isNotEmpty();
            assertThat(host.status().getFirst().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        assertThat(viajes).isEmpty();
        host.load(List.of(script("sam.teleport('Steve', {x = 30000000, y = 4096, z = -30000000, dimension = 'mod_x:mundo/sub'})"
            + " sam.teleport('Steve', {x = -30000000, y = -4096, z = 30000000, dimension = 'minecraft:overworld'})", "teleport")));
        assertThat(host.status().getFirst().errors()).isEmpty();
        assertThat(viajes).hasSize(2);
    }

    @Test
    void sinCapacidadOEnElClienteNoExisteYElPuenteMinimoNoMueveANadie() {
        host.load(List.of(script("sam.log(type(sam.position) .. ',' .. type(sam.teleport))")));
        ScriptHost.client((s, text) -> log.add(text), LIMITES)
            .load(List.of(script("sam.log(type(sam.position) .. ',' .. type(sam.teleport))", "teleport")));
        new ScriptHost(new ScriptHost.Bridge() {
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
        }, LIMITES).load(List.of(script("sam.log(tostring(sam.position('Steve')) .. ',' .. tostring(sam.teleport('Steve', "
            + "{x = 0, y = 0, z = 0, dimension = 'minecraft:overworld'})))", "teleport")));
        assertThat(log).containsExactly("nil,nil", "nil,nil", "nil,false");
    }
}
