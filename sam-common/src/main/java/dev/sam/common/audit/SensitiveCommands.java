package dev.sam.common.audit;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * RF-ADM-06a (H-09 de HARDENING.md): los comandos vanilla que van a la auditoría, por su raíz
 * ({@code SAM_AUDIT_COMMANDS}), también cuando van dentro de {@code execute ... run}.
 */
public final class SensitiveCommands {

    public static final String ENV = "SAM_AUDIT_COMMANDS";
    private static final String DEFAULT = "op,deop,ban,ban-ip,pardon,pardon-ip,kick,whitelist,gamemode,give,effect,tp,teleport,kill,"
        + "clear,stop,save-off";

    private final Set<String> roots;

    private SensitiveCommands(Set<String> roots) {
        this.roots = roots;
    }

    public static SensitiveCommands fromConfig(Map<String, String> config) {
        return new SensitiveCommands(Arrays.stream(config.getOrDefault(ENV, DEFAULT).split(","))
            .map(root -> root.strip().toLowerCase(Locale.ROOT)).filter(root -> !root.isEmpty()).collect(Collectors.toUnmodifiableSet()));
    }

    /** Si el comando (con o sin {@code /}) es sensible. */
    public boolean matches(String command) {
        var words = command.strip().replaceFirst("^/", "").toLowerCase(Locale.ROOT).split("\\s+");
        if (roots.contains(words[0])) {
            return true;
        }
        // execute ... run <comando>: cuenta el comando que corre al final
        for (var i = 0; i < words.length - 1; i++) {
            if (words[i].equals("run") && roots.contains(words[i + 1])) {
                return true;
            }
        }
        return false;
    }
}
