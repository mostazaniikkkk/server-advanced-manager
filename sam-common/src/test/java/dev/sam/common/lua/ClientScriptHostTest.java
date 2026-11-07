package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
        host.load(List.of(script("lado", "sam.log(sam.side)")));
        assertThat(log).last().isEqualTo("lado: client");
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
        enServidor.load(List.of(script("srv", "sam.log(type(sam.hud) .. ',' .. type(sam.on) .. ',' .. sam.side)", "hud", "events")));
        assertThat(servidor).containsExactly("nil,function,server");
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

    // ===== messages: las dos partes de un mismo script (PROTOCOLO.md 5.7 y 8.3) =====

    private record Enviado(String script, String jugador, String canal, String datos) {
    }

    private static String datos(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    @Test
    void elClienteEnviaYRecibePorCanal() throws Exception {
        var enviados = new ArrayList<Enviado>();
        var cliente = ScriptHost.client(new ScriptHost.ClientBridge() {
            @Override
            public void log(String s, String text) {
                log.add(s + ": " + text);
            }

            @Override
            public void send(String s, String canal, byte[] bytes) {
                enviados.add(new Enviado(s, null, canal, datos(bytes)));
            }
        }, LIMITES);
        cliente.load(List.of(script("panel", """
            sam.send("hola", true)
            local primero = sam.receive("vida", function(d) sam.log("vida " .. d.valor) end)
            local segundo = sam.receive("vida", function(d) sam.log("vida nueva " .. d.valor) end)
            sam.log(tostring(primero) .. "," .. tostring(segundo) .. "," .. tostring(sam.send("x", nil)))
            """, "messages"), script("sin", "sam.log(type(sam.send))")));
        assertThat(log).containsExactly("panel: false,true,nil", "sin: nil");
        assertThat(enviados).containsExactly(new Enviado("panel", null, "hola", "02"), new Enviado("panel", null, "x", "00"));
        var tabla = new org.squiddev.cobalt.LuaTable();
        tabla.rawset("valor", org.squiddev.cobalt.ValueFactory.valueOf(7));
        assertThat(cliente.deliver("panel", java.util.Optional.empty(), "vida", LuaData.encode(tabla))).isTrue();
        assertThat(log).last().isEqualTo("panel: vida nueva 7");
        assertThat(cliente.deliver("panel", java.util.Optional.empty(), "otro", new byte[] {0})).isFalse();
        assertThat(cliente.deliver("sin", java.util.Optional.empty(), "vida", new byte[] {0})).isFalse();
        assertThat(cliente.deliver("nadie", java.util.Optional.empty(), "vida", new byte[] {0})).isFalse();
        // Un script suspendido no recibe
        cliente.load(List.of(script("lento", "sam.receive('c', function() while true do end end)", "messages")));
        assertThat(cliente.deliver("lento", java.util.Optional.empty(), "c", new byte[] {0})).isTrue();
        assertThat(cliente.status().getFirst().state()).isEqualTo(ScriptHost.State.SUSPENDED);
        assertThat(cliente.deliver("lento", java.util.Optional.empty(), "c", new byte[] {0})).isFalse();
        cliente.load(List.of(script("panel", "sam.receive('vida', function() end)", "messages")));
        assertThatThrownBy(() -> cliente.deliver("panel", java.util.Optional.empty(), "vida", new byte[] {9}))
            .isInstanceOf(dev.sam.common.proto.ProtocolException.class);
    }

    @Test
    void loQueNoSePuedeEnviarEsUnErrorDelScript() {
        var cliente = ScriptHost.client((s, text) -> log.add(text), LIMITES);
        var casos = Map.of(
            "sam.send('Mal', 1)", "canal inválido \"Mal\": [a-z0-9_], hasta 32",
            "sam.send('c', function() end)", "no se puede enviar un valor de tipo function",
            "sam.receive('Mal', function() end)", "canal inválido",
            "for i = 1, 33 do sam.send('c', i) end", "como mucho 32 mensajes por tick");
        for (var caso : casos.entrySet()) {
            cliente.load(List.of(script("s", caso.getKey(), "messages")));
            assertThat(cliente.status().getFirst().state()).as(caso.getKey()).isEqualTo(ScriptHost.State.FAILED);
            assertThat(cliente.status().getFirst().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        // 32 por tick valen, y el contador vuelve a cero en cada tick
        cliente.load(List.of(script("s", "for i = 1, 32 do sam.send('c', i) end sam.every(1, function() for i = 1, 32 do sam.send('c', i) end end)",
            "messages", "scheduler")));
        cliente.tick();
        cliente.tick();
        assertThat(cliente.status().getFirst().state()).isEqualTo(ScriptHost.State.RUNNING);
        assertThat(cliente.status().getFirst().errors()).isEmpty();
    }

    private ScriptHost servidor(List<Enviado> enviados) {
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
            public void log(String s, String text) {
                log.add(text);
            }

            @Override
            public boolean send(String s, String player, String channel, byte[] data) {
                enviados.add(new Enviado(s, player, channel, datos(data)));
                return player.equals("Steve");
            }
        }, LIMITES);
    }

    @Test
    void elServidorEnviaAUnJugadorYSabeQuienLeEscribio() throws Exception {
        var enviados = new ArrayList<Enviado>();
        var servidor = servidor(enviados);
        servidor.load(List.of(new ScriptHost.Package(new ScriptManifest("panel", "1", ScriptManifest.Side.BOTH, List.of(),
            List.of("messages"), false), Map.of("main.lua", """
                sam.log(tostring(sam.send("Steve", "abrir", {1, 2})) .. "," .. tostring(sam.send("Alex", "abrir", false)))
                sam.receive("clic", function(jugador, d) sam.log(jugador.name .. " " .. jugador.uuid .. " " .. d) end)
                """))));
        assertThat(log).containsExactly("true,false");
        assertThat(enviados).extracting(Enviado::jugador).containsExactly("Steve", "Alex");
        assertThat(enviados.getFirst().datos()).isEqualTo(datos(LuaData.encode(tablaDe(1, 2))));
        var steve = new ScriptHost.Player("Steve", "8667ba71-b85a-4004-af54-457a9734eed7");
        assertThat(servidor.deliver("panel", java.util.Optional.of(steve), "clic", LuaData.encode(LuaSandbox.lua("ok")))).isTrue();
        assertThat(log).last().isEqualTo("Steve 8667ba71-b85a-4004-af54-457a9734eed7 ok");
        // Con el Bridge por defecto (sin mensajería), sam.send devuelve false
        var mudo = new ScriptHost(new ScriptHost.Bridge() {
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
                log.add(text);
            }
        }, LIMITES);
        mudo.load(List.of(script("m", "sam.log('mudo ' .. tostring(sam.send('Steve', 'c', 1)))", "messages")));
        assertThat(log).last().isEqualTo("mudo false");
    }

    private static org.squiddev.cobalt.LuaTable tablaDe(double... valores) {
        var tabla = new org.squiddev.cobalt.LuaTable();
        for (var i = 0; i < valores.length; i++) {
            tabla.rawset(i + 1, org.squiddev.cobalt.ValueFactory.valueOf(valores[i]));
        }
        return tabla;
    }
}
