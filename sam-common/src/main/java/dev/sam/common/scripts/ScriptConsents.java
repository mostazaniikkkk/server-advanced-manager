package dev.sam.common.scripts;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * RS-LUA-05: el consentimiento de scripts recordado por servidor. Una línea por servidor:
 * {@code <pin hex>=<id>:<sha256 hex>,...}. Si el servidor vuelve a ofrecer solo scripts que el jugador
 * aceptó (mismo id y mismo hash), no se le vuelve a preguntar. Una línea rota se ignora: se pregunta de nuevo.
 */
public final class ScriptConsents {

    private static final Pattern PIN = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern ENTRY = Pattern.compile("[a-z0-9_.-]{1,64}:[0-9a-f]{1,128}");

    private final Path file;
    private final Map<String, Set<String>> servers = new TreeMap<>();

    public ScriptConsents(Path file) {
        this.file = file;
        try {
            for (var line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                var parts = line.split("=", 2);
                if (parts.length == 2 && PIN.matcher(parts[0]).matches()) {
                    servers.put(parts[0], new TreeSet<>(Arrays.stream(parts[1].split(","))
                        .filter(e -> ENTRY.matcher(e).matches()).toList()));
                }
            }
        } catch (IOException e) {
            // Sin archivo (o ilegible): no hay nada recordado y se pregunta
        }
    }

    /** {@code id:sha256hex}, lo que se recuerda de un script. */
    public static String entry(String id, byte[] sha256) {
        return id + ":" + HexFormat.of().formatHex(sha256);
    }

    /** Si el jugador ya aceptó en este servidor todos estos scripts (y la oferta no está vacía). */
    public boolean covers(String pin, Collection<String> offered) {
        var known = servers.get(pin);
        return known != null && !offered.isEmpty() && known.containsAll(offered);
    }

    /** Recuerda que el jugador aceptó estos scripts en este servidor (reemplaza lo anterior). */
    public void remember(String pin, Collection<String> accepted) {
        check(pin);
        for (var entry : accepted) {
            if (!ENTRY.matcher(entry).matches()) {
                throw new IllegalArgumentException("entrada de consentimiento inválida: " + entry);
            }
        }
        servers.put(pin, new TreeSet<>(accepted));
        save();
    }

    /** Olvida lo aceptado en este servidor: la próxima vez se pregunta. */
    public void forget(String pin) {
        check(pin);
        if (servers.remove(pin) != null) {
            save();
        }
    }

    private static void check(String pin) {
        if (!PIN.matcher(pin).matches()) {
            throw new IllegalArgumentException("pin de servidor inválido");
        }
    }

    private void save() {
        var text = new StringBuilder("# Scripts que aceptaste en cada servidor (RS-LUA-05). Borra una línea para que vuelva a preguntar.\n");
        servers.forEach((pin, entries) -> text.append(pin).append('=').append(String.join(",", entries)).append('\n'));
        try {
            Files.createDirectories(file.getParent());
            var tmp = Files.createTempFile(file.getParent(), "consents", ".tmp");
            Files.writeString(tmp, text, StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
