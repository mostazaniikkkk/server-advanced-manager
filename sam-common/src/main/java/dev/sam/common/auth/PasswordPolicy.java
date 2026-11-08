package dev.sam.common.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * RN-45 (H-06 de HARDENING.md): la política de contraseñas, que aplica el cliente antes de derivar {@code k}
 * (el servidor nunca ve la contraseña). Longitud mínima, ninguna de las ~96.000 más usadas (lista del NCSC, vía
 * SecLists) y sin el nick adentro.
 */
public final class PasswordPolicy {

    public static final String TOO_SHORT = "es demasiado corta";
    public static final String COMMON = "es de las más usadas";
    public static final String HAS_NICK = "contiene tu nick";
    /** Un nick más corto que esto no se busca dentro de la contraseña. */
    private static final int MIN_NICK = 3;
    private static final String LIST = "common-passwords.txt.gz";

    private final Set<String> common;

    private PasswordPolicy(Set<String> common) {
        this.common = common;
    }

    /** Carga la lista incluida (unos 800 KB en memoria): el cliente lo hace una vez. */
    public static PasswordPolicy load() {
        var words = new HashSet<String>();
        try (var in = new BufferedReader(new InputStreamReader(
                new GZIPInputStream(PasswordPolicy.class.getResourceAsStream(LIST)), StandardCharsets.US_ASCII))) {
            in.lines().forEach(words::add);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return new PasswordPolicy(Set.copyOf(words));
    }

    /** El primer problema de la contraseña, o vacío si sirve. */
    public Optional<String> check(String password, String nick, int minLength) {
        if (password.length() < minLength) {
            return Optional.of(TOO_SHORT);
        }
        var lower = password.toLowerCase(Locale.ROOT);
        if (common.contains(lower)) {
            return Optional.of(COMMON);
        }
        if (nick.length() >= MIN_NICK && lower.contains(nick.toLowerCase(Locale.ROOT))) {
            return Optional.of(HAS_NICK);
        }
        return Optional.empty();
    }

    int commonCount() {
        return common.size();
    }
}
