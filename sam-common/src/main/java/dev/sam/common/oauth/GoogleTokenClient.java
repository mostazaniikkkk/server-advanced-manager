package dev.sam.common.oauth;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Optional;

import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

/**
 * El canje del código en Google (REQUERIMIENTOS 5.5, paso 5): lo hace el servidor con el
 * {@code code_verifier} y el {@code client_secret}, que nunca salen de él (RS-OAUTH-04). Devuelve el ID
 * token sin validar: eso es de {@link IdTokenValidator}.
 */
public final class GoogleTokenClient {

    public record Response(int status, String body) {
    }

    /** Un POST {@code application/x-www-form-urlencoded}; en el servidor, con {@code java.net.http}. */
    @FunctionalInterface
    public interface Http {
        Response post(String url, String form) throws IOException;
    }

    private final String clientId;
    private final String clientSecret;
    private final Http http;

    public GoogleTokenClient(String clientId, String clientSecret, Http http) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.http = http;
    }

    public Optional<String> exchange(String code, String verifier, String redirectUri) {
        var params = new LinkedHashMap<String, String>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        params.put("redirect_uri", redirectUri);
        params.put("code_verifier", verifier);
        try {
            var response = http.post(GoogleOidc.TOKEN, GoogleOidc.form(params));
            if (response.status() < 200 || response.status() >= 300) {
                return Optional.empty();
            }
            var json = JsonParser.parseString(response.body());
            if (!json.isJsonObject()) {
                return Optional.empty();
            }
            return json.getAsJsonObject().get("id_token") instanceof JsonPrimitive token && token.isString()
                ? Optional.of(token.getAsString()) : Optional.empty();
        } catch (IOException | JsonParseException e) {
            return Optional.empty();
        }
    }

    /** Sin el secreto (RS-OAUTH-04). */
    @Override
    public String toString() {
        return "GoogleTokenClient[client_id=" + clientId + ", client_secret=***]";
    }
}
