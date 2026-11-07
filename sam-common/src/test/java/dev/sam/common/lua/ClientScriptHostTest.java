package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.scripts.ScriptManifest;

/**
 * El host de scripts del cliente (API de cliente v0, PROTOCOLO.md 8.3, RF-LUA-06): la misma sandbox, solo
 * las capacidades del cliente, y el HUD como datos que el render dibuja sin ejecutar Lua.
 */
class ClientScriptHostTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);

    private final List<String> log = new ArrayList<>();
    private final ScriptHost host = ScriptHost.client((script, text) -> log.add(script + ": " + text), LIMITES);

    private static ScriptHost.Package script(String id, String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest(id, "1.0", ScriptManifest.Side.CLIENT, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main));
    }

    private ScriptHost.State estado(String id) {
        return host.status().stream().filter(s -> s.id().equals(id)).findFirst().orElseThrow().state();
    }

    @Test
    void enElClienteSoloExistenLasCapacidadesDelCliente() {
        var tipos = "sam.log(table.concat({type(sam.on), type(sam.players), type(sam.tell), type(sam.command), type(sam.after), type(sam.hud)}, ','))";
        host.load(List.of(script("todo", tipos, "events", "players", "chat", "commands", "scheduler", "hud"), script("nada", tipos)));
        assertThat(log).containsExactly("todo: nil,nil,nil,nil,function,table", "nada: nil,nil,nil,nil,nil,nil");
        // Y en el servidor, hud no existe
        var servidor = new ArrayList<String>();
        var enServidor = new ScriptHost(new ScriptHost.Bridge() {
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
            public void log(String s, String text) {
                servidor.add(text);
            }
        }, LIMITES);
        enServidor.load(List.of(script("srv", "sam.log(type(sam.hud) .. ',' .. type(sam.on))", "hud", "events")));
        assertThat(servidor).containsExactly("nil,function");
        assertThat(enServidor.hud()).isEmpty();
    }

    @Test
    void losTextosDelHudSeCreanReemplazanYBorran() {
        host.load(List.of(script("panel", """
            sam.hud.text("vida", "Vida: 20")
            sam.hud.text("oro", "§6Oro: 5", {anchor = "bottom_right", x = -4, y = -12, color = 0xFFAA00})
            sam.hud.text("tmp", "se va")
            sam.hud.text("vida", "Vida: 19", {anchor = "top", y = 2})
            sam.log(tostring(sam.hud.remove("tmp")) .. "," .. tostring(sam.hud.remove("no_existe")))
            """, "hud")));
        assertThat(log).containsExactly("panel: true,false");
        assertThat(estado("panel")).isEqualTo(ScriptHost.State.RUNNING);
        assertThat(host.hud()).containsExactly(
            new ScriptHost.HudText("panel", "vida", "Vida: 19", ScriptHost.Anchor.TOP, 0, 2, 0xFFFFFF),
            new ScriptHost.HudText("panel", "oro", "Oro: 5", ScriptHost.Anchor.BOTTOM_RIGHT, -4, -12, 0xFFAA00));
        host.load(List.of(script("otro", "sam.hud.text('a', 'x') sam.hud.text('b', 'y') sam.log(sam.hud.clear()) sam.hud.text('c', 'z')", "hud")));
        assertThat(log).last().isEqualTo("otro: 2");
        assertThat(host.hud()).extracting(ScriptHost.HudText::id).containsExactly("c");
    }

    @Test
    void loQueNoCumpleLasReglasEsUnErrorDelScript() {
        var casos = Map.of(
            "sam.hud.text('Mal', 'x')", "id de HUD inválido \"Mal\": [a-z0-9_], hasta 32",
            "sam.hud.text('a', string.rep('x', 257))", "el texto supera los 256 caracteres",
            "sam.hud.text('a', 'x', {anchor = 'arriba'})", "ancla desconocida \"arriba\"",
            "sam.hud.text('a', 'x', {x = 4097})", "x e y deben estar entre -4096 y 4096",
            "sam.hud.text('a', 'x', {y = -4097})", "x e y deben estar entre -4096 y 4096",
            "sam.hud.text('a', 'x', {color = 0x1000000})", "color debe ser 0xRRGGBB",
            "sam.hud.text('a', 'x', {color = -1})", "color debe ser 0xRRGGBB",
            "for i = 1, 65 do sam.hud.text('t' .. i, 'x') end", "como mucho 64 textos por script");
        for (var caso : casos.entrySet()) {
            host.load(List.of(script("s", caso.getKey(), "hud")));
            assertThat(estado("s")).as(caso.getKey()).isEqualTo(ScriptHost.State.FAILED);
            assertThat(host.status().getFirst().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        // Los límites justos valen
        host.load(List.of(script("s", """
            for i = 1, 64 do sam.hud.text('t' .. i, string.rep('x', 256)) end
            sam.hud.text('t1', 'x', {x = 4096, y = -4096, color = 0xFFFFFF})
            sam.hud.text('t2', 'x', {x = -4096, y = 4096, color = 0})
            sam.hud.text(string.rep('a', 32), 'x')
            """, "hud")));
        assertThat(estado("s")).isEqualTo(ScriptHost.State.FAILED);
        assertThat(host.status().getFirst().errors().getFirst()).contains("como mucho 64 textos por script");
        host.load(List.of(script("s", """
            for i = 1, 63 do sam.hud.text('t' .. i, string.rep('x', 256)) end
            sam.hud.text('t1', 'x', {x = 4096, y = -4096, color = 0xFFFFFF})
            sam.hud.text('t2', 'x', {x = -4096, y = 4096, color = 0})
            sam.hud.text(string.rep('a', 32), 'x')
            sam.hud.text('t3', 'lleno')
            """, "hud")));
        assertThat(estado("s")).isEqualTo(ScriptHost.State.RUNNING);
        assertThat(host.hud().get(2).text()).as("con 64, reemplazar uno vale").isEqualTo("lleno");
        assertThat(host.hud()).hasSize(64).first().isEqualTo(new ScriptHost.HudText("s", "t1", "x", ScriptHost.Anchor.TOP_LEFT, 4096, -4096, 0xFFFFFF));
        assertThat(host.hud().get(1)).isEqualTo(new ScriptHost.HudText("s", "t2", "x", ScriptHost.Anchor.TOP_LEFT, -4096, 4096, 0));
    }

    @Test
    void todasLasAnclasTienenNombre() {
        var lua = new StringBuilder();
        for (var nombre : List.of("top_left", "top", "top_right", "left", "center", "right", "bottom_left", "bottom", "bottom_right")) {
            lua.append("sam.hud.text('").append(nombre).append("', 'x', {anchor = '").append(nombre).append("'})\n");
        }
        host.load(List.of(script("anclas", lua.toString(), "hud")));
        assertThat(host.hud()).extracting(ScriptHost.HudText::anchor).containsExactly(ScriptHost.Anchor.values());
    }

    @Test
    void unScriptSuspendidoOFallidoNoDibujaYElRelojEsDelCliente() {
        host.load(List.of(
            script("bucle", "sam.hud.text('a', 'antes') sam.after(2, function() while true do end end)", "hud", "scheduler"),
            script("reloj", "local n = 0 sam.every(1, function() n = n + 1 sam.hud.text('n', tostring(n)) end)", "hud", "scheduler"),
            script("roto", "sam.hud.text('r', 'x') error('falla')", "hud")));
        assertThat(host.hud()).extracting(ScriptHost.HudText::script).containsExactly("bucle");
        host.tick();
        assertThat(host.hud()).extracting(ScriptHost.HudText::text).containsExactly("antes", "1");
        host.tick();
        assertThat(estado("bucle")).isEqualTo(ScriptHost.State.SUSPENDED);
        assertThat(host.hud()).extracting(ScriptHost.HudText::text).containsExactly("2");
        host.load(List.of());
        assertThat(host.hud()).isEmpty();
    }
}
