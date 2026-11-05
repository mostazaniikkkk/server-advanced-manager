package dev.sam.common.config;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Formato del {@code .env} del servidor (RF-CFG-01). Una línea por clave {@code CLAVE=valor};
 * {@code #} empieza un comentario si inicia la línea o va precedido de espacio. Los valores pueden ir
 * entre comillas dobles (con escapes {@code \"}, {@code \\} y {@code \n}) o simples (literales). Una
 * línea que no se entiende no se adivina: se rechaza con su número (RF-CFG-04).
 */
public final class DotEnv {

    private static final Pattern KEY = Pattern.compile("[A-Z][A-Z0-9_]*");

    private DotEnv() {
    }

    /**
     * @return las claves en orden de aparición
     * @throws IllegalArgumentException si alguna línea es inválida o una clave se repite
     */
    public static Map<String, String> parse(String text) {
        var values = new LinkedHashMap<String, String>();
        var definedAt = new HashMap<String, Integer>();
        var lines = text.replace("﻿", "").split("\r?\n", -1);
        for (int i = 0; i < lines.length; i++) {
            var number = i + 1;
            var line = lines[i].strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            var equals = line.indexOf('=');
            if (equals < 0) {
                throw error(number, "se esperaba CLAVE=valor");
            }
            var key = line.substring(0, equals).strip();
            if (!KEY.matcher(key).matches()) {
                throw error(number, "clave inválida \"" + key + "\"");
            }
            var previous = definedAt.putIfAbsent(key, number);
            if (previous != null) {
                throw error(number, key + " repetida (ya definida en la línea " + previous + ")");
            }
            values.put(key, value(line.substring(equals + 1), number));
        }
        return Collections.unmodifiableMap(values);
    }

    private static String value(String raw, int number) {
        var text = raw.stripLeading();
        if (text.startsWith("\"")) {
            return doubleQuoted(text, number);
        }
        if (text.startsWith("'")) {
            var end = text.indexOf('\'', 1);
            if (end == -1) {
                throw error(number, "comillas sin cerrar");
            }
            return afterQuotes(text, end, text.substring(1, end), number);
        }
        // Comentario: un # precedido de espacio (el raw conserva el espacio después del =)
        for (int i = 1; i < raw.length(); i++) {
            if (raw.charAt(i) == '#' && Character.isWhitespace(raw.charAt(i - 1))) {
                return raw.substring(0, i).strip();
            }
        }
        return text;
    }

    private static String doubleQuoted(String text, int number) {
        var out = new StringBuilder();
        for (int i = 1; i < text.length(); i++) {
            var c = text.charAt(i);
            if (c == '"') {
                return afterQuotes(text, i, out.toString(), number);
            }
            if (c == '\\' && i + 1 < text.length()) {
                var next = text.charAt(++i);
                out.append(switch (next) {
                    case '"', '\\' -> next;
                    case 'n' -> '\n';
                    default -> throw error(number, "escape inválido \\" + next);
                });
            } else {
                out.append(c);
            }
        }
        throw error(number, "comillas sin cerrar");
    }

    /** Después de cerrar las comillas solo puede haber espacio y, tras él, un comentario. */
    private static String afterQuotes(String text, int closing, String value, int number) {
        var rest = text.substring(closing + 1);
        var trimmed = rest.strip();
        if (!trimmed.isEmpty() && !(trimmed.startsWith("#") && Character.isWhitespace(rest.charAt(0)))) {
            throw error(number, "texto después de las comillas");
        }
        return value;
    }

    private static IllegalArgumentException error(int line, String message) {
        return new IllegalArgumentException(".env, línea " + line + ": " + message);
    }
}
