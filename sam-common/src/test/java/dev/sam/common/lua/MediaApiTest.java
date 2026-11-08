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
 * Las imágenes desde Lua (capacidad {@code media}, docs/plugins/sam-mensajes.md): el script pide una captura,
 * un archivo o una descarga y recibe el resultado después; nunca ve archivos ni bytes, solo ids.
 */
class MediaApiTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);
    private static final String ID = "0123456789abcdef0123456789abcdef";

    private final List<String> log = new ArrayList<>();
    private final List<String> pedidos = new ArrayList<>();
    private boolean puede = true;

    private final ScriptHost host = ScriptHost.client(new ScriptHost.ClientBridge() {
        @Override
        public void log(String script, String text) {
            log.add(text);
        }

        @Override
        public boolean requestMedia(String script, int request, String source) {
            pedidos.add(script + " " + request + " " + source);
            return puede;
        }

        @Override
        public boolean fetchMedia(String script, int request, String id) {
            pedidos.add(script + " " + request + " fetch " + id);
            return puede;
        }

        @Override
        public boolean openScreen(String script, ScreenSpec spec) {
            log.add("pantalla " + spec.widgets());
            return true;
        }
    }, LIMITES);

    private static ScriptHost.Package script(String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest("chat", "1", ScriptManifest.Side.CLIENT, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main));
    }

    @Test
    void capturaArchivoYDescargaLleganDespues() {
        host.load(List.of(script("""
            sam.log(tostring(sam.media.capture(function(id, motivo) sam.log("captura " .. tostring(id) .. " " .. tostring(motivo)) end)))
            sam.media.pick(function(id, motivo) sam.log("archivo " .. tostring(id) .. " " .. tostring(motivo)) end)
            sam.media.fetch("%s", function(id, motivo) sam.log("bajada " .. tostring(id) .. " " .. tostring(motivo)) end)
            """.formatted(ID), "media")));
        assertThat(pedidos).containsExactly("chat 1 capture", "chat 2 pick", "chat 3 fetch " + ID);
        assertThat(log).containsExactly("true");
        assertThat(host.mediaResult("chat", 1, Optional.of(ID), Optional.empty())).isTrue();
        assertThat(host.mediaResult("chat", 2, Optional.empty(), Optional.of("cancelado"))).isTrue();
        assertThat(host.mediaResult("chat", 3, Optional.of(ID), Optional.empty())).isTrue();
        assertThat(log).containsExactly("true", "captura " + ID + " nil", "archivo nil cancelado", "bajada " + ID + " nil");
        // Cada pedido se responde una sola vez
        assertThat(host.mediaResult("chat", 1, Optional.of(ID), Optional.empty())).isFalse();
        assertThat(host.mediaResult("otro", 1, Optional.of(ID), Optional.empty())).isFalse();
        // Un script suspendido ya no recibe la respuesta
        host.load(List.of(script("sam.media.capture(function() end) function colgar() while true do end end", "media")));
        host.call("chat", "colgar");
        assertThat(host.status().getFirst().state()).isEqualTo(ScriptHost.State.SUSPENDED);
        assertThat(host.mediaResult("chat", 1, Optional.of(ID), Optional.empty())).isFalse();
    }

    @Test
    void siElJuegoNoPuedeNoQuedaPendienteYHayTope() {
        puede = false;
        host.load(List.of(script("sam.log(tostring(sam.media.pick(function() sam.log('nunca') end)))", "media")));
        assertThat(log).containsExactly("false");
        assertThat(host.mediaResult("chat", 1, Optional.of(ID), Optional.empty())).isFalse();
        puede = true;
        host.load(List.of(script("for i = 1, 5 do sam.media.capture(function() end) end", "media")));
        assertThat(host.status().getFirst().errors().getFirst()).contains("como mucho 4 imágenes en curso");
        host.load(List.of(script("for i = 1, 4 do sam.media.capture(function() end) end function otra() sam.media.capture(function() end) end",
            "media")));
        assertThat(host.status().getFirst().errors()).isEmpty();
        // Al responder una, hay lugar para otra (y solo una)
        host.mediaResult("chat", 1, Optional.empty(), Optional.of("x"));
        assertThat(host.call("chat", "otra").error()).isEmpty();
        assertThat(host.call("chat", "otra").error()).hasValueSatisfying(e -> assertThat(e).contains("como mucho 4 imágenes en curso"));
    }

    @Test
    void elWidgetYLaDescargaExigenUnIdValido() {
        host.load(List.of(script("""
            sam.screen.open({title = "x", width = 100, height = 100, widgets = {{type = "media", id = "%s", x = 1, y = 2, w = 64, h = 32}}})
            """.formatted(ID), "media", "screens")));
        assertThat(log).containsExactly("pantalla [Media[id=" + ID + ", x=1, y=2, w=64, h=32]]");
        for (var malo : List.of("sam.media.fetch('XYZ', function() end)", "sam.media.fetch('" + ID.toUpperCase() + "', function() end)",
                "sam.screen.open({title = 'x', width = 100, height = 100, widgets = {{type = 'media', id = 'no'}}})")) {
            host.load(List.of(script(malo, "media", "screens")));
            assertThat(host.status().getFirst().errors().getFirst()).as(malo).contains("id de imagen inválido");
        }
        host.load(List.of(script("sam.screen.open({title = 'x', width = 100, height = 100, widgets = {{type = 'media', id = '"
            + ID + "', w = 513}}})", "media", "screens")));
        assertThat(host.status().getFirst().errors().getFirst()).contains("w y h de una imagen deben estar entre 1 y 512");
        // Sin w ni h, 128×128
        log.clear();
        host.load(List.of(script("sam.screen.open({title = 'x', width = 100, height = 100, widgets = {{type = 'media', id = '"
            + ID + "'}}})", "media", "screens")));
        assertThat(log).containsExactly("pantalla [Media[id=" + ID + ", x=0, y=0, w=128, h=128]]");
        // El widget sin la capacidad media no existe
        host.load(List.of(script("sam.screen.open({title = 'x', width = 100, height = 100, widgets = {{type = 'media', id = '"
            + ID + "'}}})", "screens")));
        assertThat(host.status().getFirst().errors().getFirst()).contains("widget de tipo desconocido \"media\"");
    }

    @Test
    void elServidorComparteYElPuenteMinimoNoHaceNada() {
        var compartidos = new ArrayList<String>();
        var servidor = new ScriptHost(new ScriptHost.Bridge() {
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
            public boolean shareMedia(String id, String from, String to) {
                compartidos.add(id + " " + from + " " + to);
                return to.equals("Alex");
            }
        }, LIMITES);
        servidor.load(List.of(new ScriptHost.Package(new ScriptManifest("chat", "1", ScriptManifest.Side.SERVER, List.of(), List.of("media"),
            false), Map.of("main.lua", "sam.log(tostring(sam.media.share('%s', 'Steve', 'Alex')) .. ',' .. tostring(sam.media.share('%s', 'Steve', 'Bob')) .. ',' .. type(sam.media.capture))".formatted(ID, ID)))));
        assertThat(compartidos).containsExactly(ID + " Steve Alex", ID + " Steve Bob");
        assertThat(log).containsExactly("true,false,nil");
        servidor.load(List.of(new ScriptHost.Package(new ScriptManifest("chat", "1", ScriptManifest.Side.SERVER, List.of(), List.of("media"),
            false), Map.of("main.lua", "sam.media.share('no', 'a', 'b')"))));
        assertThat(servidor.status().getFirst().errors().getFirst()).contains("id de imagen inválido");
        // Puentes mínimos: el servidor no comparte; el cliente no captura, no elige ni descarga, y no hay share
        var minimoCliente = ScriptHost.client((s, text) -> log.add(text), LIMITES);
        minimoCliente.load(List.of(script("local f = function() end sam.log(tostring(sam.media.capture(f)) .. tostring(sam.media.pick(f)) .. "
            + "tostring(sam.media.fetch('" + ID + "', f)) .. type(sam.media.share))", "media")));
        assertThat(log).last().isEqualTo("falsefalsefalsenil");
        var minimoServidor = new ScriptHost(new ScriptHost.Bridge() {
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
        minimoServidor.load(List.of(new ScriptHost.Package(new ScriptManifest("chat", "1", ScriptManifest.Side.SERVER, List.of(),
            List.of("media"), false), Map.of("main.lua", "sam.log(tostring(sam.media.share('" + ID + "', 'a', 'b')))"))));
        assertThat(log).last().isEqualTo("false");
        // Sin la capacidad no existe
        host.load(List.of(script("sam.log(type(sam.media))")));
        assertThat(log).last().isEqualTo("nil");
    }
}
