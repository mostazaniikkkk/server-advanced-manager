package dev.sam.common.oauth;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Lo que llega al servidor HTTP efímero del cliente (REQUERIMIENTOS 5.5, paso 4): Google redirige a
 * {@code http://127.0.0.1:<puerto>/?state=...&code=...}. El cliente solo reenvía el código si el
 * {@code state} es el de la URL que abrió.
 */
public final class LoopbackRedirect {

    private LoopbackRedirect() {
    }

    /** @param requestTarget la ruta y la query del request ({@code /?state=...&code=...}) */
    public static Optional<String> code(String requestTarget, String expectedState) {
        if (!requestTarget.startsWith("/?")) {
            return Optional.empty();
        }
        var params = params(requestTarget.substring(2));
        if (params.containsKey("error") || !expectedState.equals(params.get("state"))) {
            return Optional.empty();
        }
        return Optional.ofNullable(params.get("code")).filter(code -> !code.isEmpty());
    }

    /** El {@code state} de la URL de autorización que manda el servidor. */
    public static Optional<String> stateOf(String authorizationUrl) {
        var query = URI.create(authorizationUrl).getRawQuery();
        if (query == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(params(query).get("state"));
    }

    /** @return vacío si un parámetro se repite (no se adivina cuál vale) */
    private static Map<String, String> params(String query) {
        var params = new HashMap<String, String>();
        for (var pair : query.split("&")) {
            var parts = pair.split("=", 2);
            if (parts.length < 2) {
                continue;
            }
            var key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            if (params.put(key, URLDecoder.decode(parts[1], StandardCharsets.UTF_8)) != null) {
                return Map.of();
            }
        }
        return params;
    }
}
