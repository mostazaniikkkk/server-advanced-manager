package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.scripts.ScriptManifest;

/**
 * Links desde un script (capacidad {@code links}, docs/plugins/sam-mensajes.md): solo {@code http(s)}, y el
 * juego siempre pide confirmación antes de abrirlos.
 */
class LinksApiTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);

    private final List<String> log = new ArrayList<>();
    private final List<String> abiertos = new ArrayList<>();
    private boolean acepta = true;

    private final ScriptHost host = ScriptHost.client(new ScriptHost.ClientBridge() {
        @Override
        public void log(String script, String text) {
            log.add(text);
        }

        @Override
        public boolean openUrl(String script, String url) {
            abiertos.add(script + " " + url);
            return acepta;
        }
    }, LIMITES);

    private static ScriptHost.Package script(String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest("chat", "1", ScriptManifest.Side.CLIENT, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main));
    }

    @Test
    void unLinkHttpsPasaAlJuegoParaConfirmarlo() {
        host.load(List.of(script("""
            sam.log(tostring(sam.open_url("https://example.com/a?b=1#c")))
            sam.log(tostring(sam.open_url("HTTP://Example.com")))
            """, "links")));
        assertThat(abiertos).containsExactly("chat https://example.com/a?b=1#c", "chat HTTP://Example.com");
        assertThat(log).containsExactly("true", "true");
        acepta = false;
        host.load(List.of(script("sam.log(tostring(sam.open_url('https://example.com')))", "links")));
        assertThat(log).last().isEqualTo("false");
    }

    @Test
    void soloHttpYHttpsBienFormados() {
        var malos = List.of("file:///C:/Windows", "javascript:alert(1)", "ftp://x.com", "https://", "https:///x", "https://ex ample.com",
            "https://example.com/\u0007", "example.com", "https://" + "a".repeat(505) + ".com");
        for (var malo : malos) {
            host.load(List.of(script("sam.open_url(...)".replace("...", "'" + malo.replace("\u0007", "\\7") + "'"), "links")));
            assertThat(host.status().getFirst().state()).as(malo).isEqualTo(ScriptHost.State.FAILED);
            assertThat(host.status().getFirst().errors().getFirst()).as(malo).contains("link inválido");
        }
        assertThat(abiertos).isEmpty();
        // Justo 512 caracteres vale
        var justo = "https://" + "a".repeat(500) + ".com";
        assertThat(justo).hasSize(512);
        host.load(List.of(script("sam.open_url('" + justo + "')", "links")));
        assertThat(abiertos).containsExactly("chat " + justo);
    }

    @Test
    void sinCapacidadOEnElServidorNoExisteYElPuenteMinimoNoAbre() {
        host.load(List.of(script("sam.log(type(sam.open_url))")));
        var minimo = ScriptHost.client((s, text) -> log.add(text), LIMITES);
        minimo.load(List.of(script("sam.log(tostring(sam.open_url('https://example.com')))", "links")));
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
        }, LIMITES);
        servidor.load(List.of(script("sam.log(type(sam.open_url))", "links")));
        assertThat(log).containsExactly("nil", "false", "nil");
    }
}
