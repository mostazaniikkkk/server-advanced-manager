package dev.sam.common.lua;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Las teclas que eligió el jugador para los scripts de cada servidor (RF-LUA-06e, PROTOCOLO.md 8.3): el
 * archivo {@code script-keys.properties}, una línea {@code <servidor>.<script>.<id>=<tecla>}. La primera vez
 * que un script pide una tecla se agrega la suya; después manda lo que diga el jugador. Un valor que no es
 * una tecla vale como desactivada.
 */
public final class ScriptKeys {

    public static final String NONE = "none";
    private static final Pattern KEY = Pattern.compile("[a-z0-9]|f[1-9]|f1[0-2]|none");
    private static final String HEADER = "# Teclas de los scripts de servidor: <servidor>.<script>.<id>=<tecla>"
        + " (a-z, 0-9, f1-f12 o none)\n";

    /** Una tecla de un script de un servidor. */
    public record Choice(String script, String id, String key) {
    }

    private final TreeMap<String, String> entries = new TreeMap<>();
    private boolean dirty;

    private ScriptKeys() {
    }

    /** Lee el archivo; las líneas vacías, los comentarios ({@code #}, {@code !}) y las que no tienen nombre antes del {@code =} se ignoran. */
    public static ScriptKeys parse(String text) {
        var keys = new ScriptKeys();
        for (var line : text.split("\n")) {
            var trimmed = line.strip();
            var equals = trimmed.indexOf('=');
            if (trimmed.startsWith("#") || trimmed.startsWith("!") || equals <= 0) {
                continue;
            }
            keys.entries.put(trimmed.substring(0, equals).strip(), trimmed.substring(equals + 1).strip().toLowerCase(Locale.ROOT));
        }
        return keys;
    }

    /** {@code a}..{@code z}, {@code 0}..{@code 9}, {@code f1}..{@code f12} o {@code none}. */
    public static boolean valid(String key) {
        return KEY.matcher(key).matches();
    }

    /** La tecla de ese script; si el jugador nunca eligió, se guarda y se usa {@code fallback}. */
    public String choose(String server, String script, String id, String fallback) {
        var entry = server + "." + script + "." + id;
        var chosen = entries.get(entry);
        if (chosen == null) {
            entries.put(entry, fallback);
            dirty = true;
            chosen = fallback;
        }
        return valid(chosen) ? chosen : NONE;
    }

    /** @throws IllegalArgumentException si no es una tecla válida (ni {@code none}) */
    public void set(String server, String script, String id, String key) {
        var name = key.toLowerCase(Locale.ROOT);
        if (!valid(name)) {
            throw new IllegalArgumentException("tecla desconocida \"" + key + "\" (a-z, 0-9, f1-f12 o none)");
        }
        entries.put(server + "." + script + "." + id, name);
        dirty = true;
    }

    /** Las teclas de los scripts de un servidor, por script e id. */
    public List<Choice> of(String server) {
        var prefix = server + ".";
        var choices = new ArrayList<Choice>();
        entries.forEach((entry, key) -> {
            if (entry.startsWith(prefix)) {
                var rest = entry.substring(prefix.length());
                var dot = rest.indexOf('.');
                choices.add(new Choice(rest.substring(0, dot), rest.substring(dot + 1), key));
            }
        });
        return choices;
    }

    public String text() {
        var out = new StringBuilder(HEADER);
        entries.forEach((entry, key) -> out.append(entry).append('=').append(key).append('\n'));
        return out.toString();
    }

    /** Si cambió desde la última vez que se guardó. */
    public boolean dirty() {
        return dirty;
    }

    public void saved() {
        dirty = false;
    }
}
