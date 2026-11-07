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
 * El host de scripts del servidor (RF-LUA-02/03, API v0 de PROTOCOLO.md 8.3): cada script solo ve las
 * funciones de las capacidades que declaró (RS-LUA-04), sus errores quedan aislados y un script que se
 * pasa de sus límites se suspende (RS-LUA-03).
 */
class ScriptHostTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);
    private static final ScriptHost.Player STEVE = new ScriptHost.Player("Steve", "8667ba71-b85a-4004-af54-457a9734eed7");
    private static final ScriptHost.Player ALEX = new ScriptHost.Player("Alex", "ec561538-f3fd-461d-aff5-086b22154bce");

    /** El servidor de mentira: guarda lo que los scripts le piden. */
    private static final class Servidor implements ScriptHost.Bridge {
        final List<String> log = new ArrayList<>();
        final List<String> mensajes = new ArrayList<>();
        List<ScriptHost.Player> enLinea = List.of(STEVE, ALEX);

        @Override
        public List<ScriptHost.Player> players() {
            return enLinea;
        }

        @Override
        public void tell(String player, String text) {
            mensajes.add(player + ": " + text);
        }

        @Override
        public void broadcast(String text) {
            mensajes.add("*: " + text);
        }

        @Override
        public void log(String script, String text) {
            log.add(script + ": " + text);
        }
    }

    private final Servidor servidor = new Servidor();
    private final ScriptHost host = new ScriptHost(servidor, LIMITES);

    private static ScriptHost.Package script(String id, String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest(id, "1.0", ScriptManifest.Side.SERVER, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main));
    }

    private ScriptHost.Status estado(String id) {
        return host.status().stream().filter(s -> s.id().equals(id)).findFirst().orElseThrow();
    }

    @Test
    void cadaScriptSoloVeLasFuncionesDeSusCapacidades() {
        host.load(List.of(
            script("todo", "sam.log(table.concat({type(sam.on), type(sam.after), type(sam.players), type(sam.tell)}, ','))",
                "events", "scheduler", "players", "chat"),
            script("nada", "sam.log(table.concat({type(sam.on), type(sam.after), type(sam.players), type(sam.tell)}, ','))")));
        assertThat(servidor.log).containsExactly("todo: function,function,function,function", "nada: nil,nil,nil,nil");
        assertThat(estado("todo").state()).isEqualTo(ScriptHost.State.RUNNING);
    }

    @Test
    void losEventosLleganConElJugadorYElChat() {
        host.load(List.of(script("saludo", """
            sam.on('join', function(p) sam.tell(p.name, 'Hola ' .. p.name .. ' (' .. p.uuid:sub(1, 4) .. ')') end)
            sam.on('chat', function(p, texto) sam.broadcast(p.name .. ' dijo ' .. texto) end)
            sam.on('quit', function(p) sam.log('se fue ' .. p.name) end)
            """, "events", "chat")));
        host.fire(ScriptHost.Event.JOIN, STEVE, Optional.empty());
        host.fire(ScriptHost.Event.CHAT, ALEX, Optional.of("¡hola, ñandú!"));
        host.fire(ScriptHost.Event.QUIT, STEVE, Optional.empty());
        assertThat(servidor.mensajes).containsExactly("Steve: Hola Steve (8667)", "*: Alex dijo ¡hola, ñandú!");
        assertThat(servidor.log).containsExactly("saludo: se fue Steve");
    }

    @Test
    void elSchedulerCuentaTicksYSePuedeCancelar() {
        host.load(List.of(script("reloj", """
            n = 0
            sam.after(2, function() sam.log('después') end)
            local id = sam.every(1, function() n = n + 1 sam.log('tick ' .. n) end)
            sam.after(3, function() sam.cancel(id) end)
            """, "scheduler")));
        for (var i = 0; i < 6; i++) {
            host.tick();
        }
        // Las que vencen en el mismo tick corren en el orden en que se crearon
        assertThat(servidor.log).containsExactly("reloj: tick 1", "reloj: después", "reloj: tick 2", "reloj: tick 3");
    }

    @Test
    void sePuedenListarLosJugadores() {
        host.load(List.of(script("lista", """
            local nombres = {}
            for _, p in ipairs(sam.players()) do nombres[#nombres + 1] = p.name end
            sam.log(table.concat(nombres, ','))
            """, "players")));
        assertThat(servidor.log).containsExactly("lista: Steve,Alex");
    }

    @Test
    void losArgumentosMalosSonErroresDelScript() {
        host.load(List.of(script("malo", """
            function evento() sam.on('explotar', function() end) end
            function ticks() sam.after(0, function() end) end
            function largo() sam.broadcast(string.rep('x', 257)) end
            function codigos() sam.tell('Steve', '§4rojo') end
            function func() sam.after(1, 'no es función') end
            """, "events", "scheduler", "chat")));
        assertThat(host.call("malo", "evento").error()).hasValueSatisfying(e -> assertThat(e).contains("explotar"));
        assertThat(host.call("malo", "ticks").error()).hasValueSatisfying(e -> assertThat(e).contains("1 y 72000"));
        assertThat(host.call("malo", "largo").error()).hasValueSatisfying(e -> assertThat(e).contains("256"));
        assertThat(host.call("malo", "func").error()).isPresent();
        host.call("malo", "codigos");
        assertThat(servidor.mensajes).containsExactly("Steve: rojo");
    }

    @Test
    void elTopeDeTareasYManejadoresEvitaQueUnScriptLlenePorDentro() {
        host.load(List.of(script("lleno", """
            function tareas() for i = 1, 257 do sam.after(10, function() end) end end
            function manejadores() for i = 1, 17 do sam.on('join', function() end) end end
            """, "scheduler", "events")));
        assertThat(host.call("lleno", "tareas").error()).hasValueSatisfying(e -> assertThat(e).contains("256 tareas"));
        assertThat(host.call("lleno", "manejadores").error()).hasValueSatisfying(e -> assertThat(e).contains("16 manejadores"));
    }

    @Test
    void unErrorQuedaAisladoYRegistradoPeroElScriptSigue() {
        host.load(List.of(
            script("roto", "sam.on('join', function() error('ups') end) sam.on('quit', function() sam.log('sigo vivo') end)", "events"),
            script("sano", "sam.on('join', function(p) sam.log('hola ' .. p.name) end)", "events")));
        host.fire(ScriptHost.Event.JOIN, STEVE, Optional.empty());
        host.fire(ScriptHost.Event.QUIT, STEVE, Optional.empty());
        assertThat(servidor.log).containsExactly("sano: hola Steve", "roto: sigo vivo");
        assertThat(estado("roto").state()).isEqualTo(ScriptHost.State.RUNNING);
        assertThat(estado("roto").errors()).singleElement().satisfies(e -> assertThat(e).contains("ups"));
    }

    @Test
    void unScriptQueSePasaDeSusLimitesSeSuspende() {
        host.load(List.of(script("glotón", """
            sam.on('join', function() while true do end end)
            sam.every(1, function() sam.log('no debería seguir') end)
            """, "events", "scheduler")));
        host.fire(ScriptHost.Event.JOIN, STEVE, Optional.empty());
        assertThat(estado("glotón").state()).isEqualTo(ScriptHost.State.SUSPENDED);
        host.tick();
        host.fire(ScriptHost.Event.JOIN, STEVE, Optional.empty());
        assertThat(servidor.log).isEmpty();
        assertThat(host.call("glotón", "x").error()).contains("el script está suspendido");
    }

    @Test
    void siUnManejadorLoSuspendeNoCorrenLosSiguientes() {
        host.load(List.of(script("doble", """
            sam.on('join', function() while true do end end)
            sam.on('join', function() sam.log('segundo') end)
            """, "events")));
        host.fire(ScriptHost.Event.JOIN, STEVE, Optional.empty());
        assertThat(servidor.log).isEmpty();
    }

    @Test
    void unScriptQueFallaAlCargarNoRecibeEventosNiTicks() {
        host.load(List.of(script("medio", """
            sam.on('join', function() sam.log('no') end)
            sam.every(1, function() sam.log('no') end)
            error('se rompió después de registrar')
            """, "events", "scheduler")));
        host.fire(ScriptHost.Event.JOIN, STEVE, Optional.empty());
        host.tick();
        assertThat(servidor.log).isEmpty();
        assertThat(estado("medio").state()).isEqualTo(ScriptHost.State.FAILED);
    }

    @Test
    void enUnMismoTickUnaTareaPuedeCancelarOtraYUnaSuspensionCortaElResto() {
        host.load(List.of(script("cancela", """
            local b
            sam.after(1, function() sam.cancel(b) end)
            b = sam.after(1, function() sam.log('b no debería correr') end)
            """, "scheduler"), script("suspende", """
            sam.after(1, function() while true do end end)
            sam.after(1, function() sam.log('tampoco') end)
            """, "scheduler")));
        host.tick();
        assertThat(servidor.log).isEmpty();
        assertThat(estado("suspende").state()).isEqualTo(ScriptHost.State.SUSPENDED);
    }

    @Test
    void everyRepiteCadaNTicks() {
        host.load(List.of(script("cada2", "n = 0 sam.every(2, function() n = n + 1 sam.log('vez ' .. n) end)", "scheduler")));
        for (var i = 0; i < 5; i++) {
            host.tick();
        }
        assertThat(servidor.log).containsExactly("cada2: vez 1", "cada2: vez 2");
    }

    @Test
    void losTopesSeAceptanJustoEnElBorde() {
        host.load(List.of(script("bordes", """
            function texto() sam.broadcast(string.rep('x', 256)) end
            function ticksMax() return sam.after(72000, function() end) end
            function ticksDeMas() sam.after(72001, function() end) end
            function log() sam.log(string.rep('a', 512)) sam.log(string.rep('b', 513)) end
            function vacias()
              return table.concat({select('#', sam.log('x')), select('#', sam.on('join', function() end)),
                select('#', sam.cancel(99)), select('#', sam.tell('Steve', 'x')), select('#', sam.broadcast('x'))}, ',')
            end
            """, "chat", "scheduler", "events")));
        assertThat(host.call("bordes", "texto").error()).isEmpty();
        assertThat(host.call("bordes", "ticksMax").value()).isPresent();
        assertThat(host.call("bordes", "ticksDeMas").error()).isPresent();
        host.call("bordes", "log");
        assertThat(servidor.log).containsExactly("bordes: " + "a".repeat(512), "bordes: " + "b".repeat(512) + "…");
        assertThat(host.call("bordes", "vacias").value()).contains("1,1,1,1,1");
    }

    @Test
    void seGuardanLosUltimos20Errores() {
        host.load(List.of(script("errores", "function f(n) error('fallo ' .. n) end", "events")));
        for (var i = 1; i <= 21; i++) {
            host.call("errores", "f");
        }
        assertThat(estado("errores").errors()).hasSize(20);
    }

    @Test
    void unScriptQueNoCargaQuedaFallidoYNoAfectaALosDemas() {
        host.load(List.of(script("roto", "esto no es lua"), script("sano", "sam.log('ok')")));
        assertThat(estado("roto").state()).isEqualTo(ScriptHost.State.FAILED);
        assertThat(estado("roto").errors()).hasSize(1);
        assertThat(host.call("roto", "f").error()).contains("el script no cargó");
        assertThat(estado("sano").state()).isEqualTo(ScriptHost.State.RUNNING);
        assertThat(host.call("nadie", "f").error()).contains("no hay un script nadie");
        // Recargar descarta todo lo anterior
        host.load(List.of());
        assertThat(host.status()).isEmpty();
    }
}
