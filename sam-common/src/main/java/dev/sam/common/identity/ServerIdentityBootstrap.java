package dev.sam.common.identity;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Arranque de la identidad del servidor (RF-CFG-08, RF-CFG-04, RS-NET-02).
 *
 * <p>La passphrase solo se acepta desde la variable de entorno real {@value #PASSPHRASE_ENV}. Si
 * falta en el primer arranque, se sugiere una aleatoria para que el admin la defina (no se guarda
 * en ningún lado). Ante cualquier problema el resultado es {@link Disabled}: el servidor arranca,
 * pero el login de SAM queda cerrado; nunca se regenera una identidad existente.
 */
public final class ServerIdentityBootstrap {

    public static final String PASSPHRASE_ENV = "SAM_IDENTITY_PASSPHRASE";
    private static final int SUGGESTED_BYTES = 32;

    public sealed interface Outcome permits Ready, Disabled {
    }

    /** @param created si la identidad se generó en este arranque */
    public record Ready(ServerIdentity identity, boolean created) implements Outcome {
    }

    /**
     * @param reason explicación para la consola; nunca contiene la passphrase
     * @param suggestedPassphrase solo en el primer arranque sin variable: valor aleatorio para definirla
     */
    public record Disabled(String reason, Optional<String> suggestedPassphrase) implements Outcome {
    }

    private ServerIdentityBootstrap() {
    }

    public static Outcome start(Map<String, String> env, Path file, SecureRandom random, Instant now) {
        var passphrase = env.get(PASSPHRASE_ENV);
        if (passphrase == null || passphrase.isBlank()) {
            if (Files.exists(file)) {
                return new Disabled("Falta la variable de entorno " + PASSPHRASE_ENV
                    + " para abrir la identidad existente " + file.getFileName() + ". El login de SAM queda cerrado.",
                    Optional.empty());
            }
            return new Disabled("Falta la variable de entorno " + PASSPHRASE_ENV
                + ". Defínela con el valor sugerido (no se guarda en ningún lado) y reinicia. El login de SAM queda cerrado.",
                Optional.of(suggest(random)));
        }
        try {
            var result = ServerIdentityStore.loadOrCreate(file, passphrase.toCharArray(), random, now);
            return new Ready(result.identity(), result.created());
        } catch (RuntimeException e) {
            // Los mensajes del almacén nunca incluyen la passphrase
            return new Disabled(e.getMessage() + " El login de SAM queda cerrado.", Optional.empty());
        }
    }

    private static String suggest(SecureRandom random) {
        var bytes = new byte[SUGGESTED_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
