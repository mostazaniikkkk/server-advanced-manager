package dev.sam.common.config;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Enmascarado de valores secretos en logs, {@code /sam info} y reportes (RF-CFG-06): las claves que
 * terminan en {@code _SECRET}, {@code _KEY}, {@code _PASSWORD} o {@code _PASSPHRASE}.
 */
public final class Secrets {

    public static final String MASK = "********";

    private static final List<String> SUFFIXES = List.of("_SECRET", "_KEY", "_PASSWORD", "_PASSPHRASE");

    private Secrets() {
    }

    public static boolean isSecret(String key) {
        return SUFFIXES.stream().anyMatch(key::endsWith);
    }

    /** El valor tal cual, o {@link #MASK} si la clave es secreta y el valor no está vacío. */
    public static String mask(String key, String value) {
        return isSecret(key) && !value.isEmpty() ? MASK : value;
    }

    /** Copia ordenada por clave, con los secretos enmascarados. */
    public static Map<String, String> masked(Map<String, String> values) {
        var view = new TreeMap<String, String>();
        values.forEach((key, value) -> view.put(key, mask(key, value)));
        return Collections.unmodifiableMap(view);
    }
}
