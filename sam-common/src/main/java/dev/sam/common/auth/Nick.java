package dev.sam.common.auth;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Nicks (RF-AUTH-01e, RS-AUTH-06, RN-07): la cuenta queda ligada al nick sin distinguir mayúsculas.
 * Validación {@code strict}: {@code [A-Za-z0-9_]{3,16}}.
 */
public final class Nick {

    private static final Pattern STRICT = Pattern.compile("[A-Za-z0-9_]{3,16}");

    private Nick() {
    }

    /** La clave de la cuenta: el nick en minúsculas. */
    public static String normalize(String nick) {
        return nick.toLowerCase(Locale.ROOT);
    }

    public static boolean isValid(String nick) {
        return STRICT.matcher(nick).matches();
    }
}
