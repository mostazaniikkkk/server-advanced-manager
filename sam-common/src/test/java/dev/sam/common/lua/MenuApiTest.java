package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.scripts.ScriptManifest;

/**
 * Las entradas de los plugins en el botón de Opciones de cuenta (capacidad {@code menu},
 * docs/plugins/sam-mensajes.md): el juego las ordena y, al hacer clic, avisa al script.
 */
class MenuApiTest {

    private static final ScriptLimits LIMITES = new ScriptLimits(Duration.ofMillis(200), 16L * 1024 * 1024, 64 * 1024);
    private static final byte[] ICONO = PngInfoTest.png(16, 16, 0);

    private final List<String> log = new ArrayList<>();
    private final ScriptHost host = ScriptHost.client((s, text) -> log.add(s + ": " + text), LIMITES);

    private static ScriptHost.Package script(String id, String main, String... capacidades) {
        return new ScriptHost.Package(new ScriptManifest(id, "1", ScriptManifest.Side.CLIENT, List.of(), List.of(capacidades), false),
            Map.of("main.lua", main), Map.of("assets/icono.png", ICONO));
    }

    @Test
    void lasEntradasSeOrdenanPorOrdenYTextoYAvisanAlScript() {
        host.load(List.of(
            script("mensajes", """
                sam.menu.add("abrir", "Mensajes", function() sam.log("abrir mensajes") end, {icon = "assets/icono.png", order = 10})
                sam.menu.add("ayuda", "§aAyuda", function() sam.log("ayuda") end)
                """, "menu"),
            script("tienda", "sam.menu.add('tienda', 'Tienda', function() sam.log('tienda') end, {order = 10})", "menu")));
        var entradas = host.menuEntries();
        assertThat(entradas).extracting(ScriptHost.MenuEntry::label).containsExactly("Mensajes", "Tienda", "Ayuda");
        assertThat(entradas.getFirst().icon()).hasValueSatisfying(png -> assertThat(png).isEqualTo(ICONO));
        assertThat(entradas.get(2).icon()).isEmpty();
        assertThat(entradas.get(1)).extracting(ScriptHost.MenuEntry::script, ScriptHost.MenuEntry::id, ScriptHost.MenuEntry::order)
            .containsExactly("tienda", "tienda", 10);
        assertThat(entradas.get(2).order()).isEqualTo(100);
        assertThat(host.menuClicked("mensajes", "abrir")).isTrue();
        assertThat(host.menuClicked("mensajes", "nada")).isFalse();
        assertThat(host.menuClicked("nadie", "abrir")).isFalse();
        assertThat(log).containsExactly("mensajes: abrir mensajes");
    }

    @Test
    void quitarReemplazarYTopes() {
        host.load(List.of(script("m", """
            sam.log(tostring(sam.menu.add("a", "Uno", function() end)) .. "," .. tostring(sam.menu.add("a", "Uno bis", function() end)))
            sam.log(tostring(sam.menu.remove("a")) .. "," .. tostring(sam.menu.remove("a")))
            for i = 1, 4 do sam.menu.add("e" .. i, "E" .. i, function() end) end
            sam.menu.add("e1", "Reemplazo con el menú lleno", function() end)
            """, "menu")));
        assertThat(host.menuEntries()).hasSize(4).extracting(ScriptHost.MenuEntry::label).contains("Reemplazo con el menú lleno");
        assertThat(log).containsExactly("m: false,true", "m: true,false");
        var casos = Map.of(
            "for i = 1, 5 do sam.menu.add('e' .. i, 'E', function() end) end", "como mucho 4 entradas de menú por script",
            "sam.menu.add('Mal', 'x', function() end)", "id de menú inválido \"Mal\"",
            "sam.menu.add('a', string.rep('x', 33), function() end)", "el texto supera los 32 caracteres",
            "sam.menu.add('a', '', function() end)", "el texto no puede estar vacío",
            "sam.menu.add('a', 'x', function() end, {order = 1000})", "order debe estar entre 0 y 999",
            "sam.menu.add('a', 'x', function() end, {order = -1})", "order debe estar entre 0 y 999",
            "sam.menu.add('a', 'x', function() end, {icon = 'assets/no.png'})", "no hay una imagen");
        for (var caso : casos.entrySet()) {
            host.load(List.of(script("s", caso.getKey(), "menu")));
            assertThat(host.status().getFirst().state()).as(caso.getKey()).isEqualTo(ScriptHost.State.FAILED);
            assertThat(host.status().getFirst().errors().getFirst()).as(caso.getKey()).contains(caso.getValue());
        }
        host.load(List.of(script("s", "sam.menu.add(string.rep('a', 32), string.rep('x', 32), function() end, {order = 999})"
            + " sam.menu.add('b', 'y', function() end, {order = 0})", "menu")));
        assertThat(host.menuEntries()).extracting(ScriptHost.MenuEntry::order).containsExactly(0, 999);
    }

    @Test
    void sinCapacidadEnElServidorOConElScriptCaidoNoHayEntradas() {
        host.load(List.of(script("sin", "sam.log(type(sam.menu))")));
        assertThat(log).containsExactly("sin: nil");
        host.load(List.of(script("lento", "sam.menu.add('a', 'A', function() while true do end end)", "menu")));
        assertThat(host.menuClicked("lento", "a")).isTrue();
        assertThat(host.menuEntries()).isEmpty();
        assertThat(host.menuClicked("lento", "a")).isFalse();
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
        servidor.load(List.of(script("srv", "sam.log(type(sam.menu))", "menu")));
        assertThat(log).last().isEqualTo("nil");
        assertThat(servidor.menuEntries()).isEmpty();
    }
}
