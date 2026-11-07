package dev.sam.common.oauth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.stream.Collectors;

/** Los extremos de Google para "Entrar con Google" (REQUERIMIENTOS 5.5). */
public final class GoogleOidc {

    public static final String AUTHORIZATION = "https://accounts.google.com/o/oauth2/v2/auth";
    public static final String TOKEN = "https://oauth2.googleapis.com/token";
    public static final String JWKS = "https://www.googleapis.com/oauth2/v3/certs";

    private GoogleOidc() {
    }

    /**
     * La URL de autorización: solo el scope {@code openid} (RS-OAUTH-01), code + PKCE S256, y siempre el
     * selector de cuenta para no vincular por accidente la cuenta con sesión abierta en el navegador.
     */
    public static String authorizationUrl(String clientId, String redirectUri, String state, String nonce, String challenge) {
        var params = new LinkedHashMap<String, String>();
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        params.put("response_type", "code");
        params.put("scope", "openid");
        params.put("state", state);
        params.put("nonce", nonce);
        params.put("code_challenge", challenge);
        params.put("code_challenge_method", "S256");
        params.put("prompt", "select_account");
        return AUTHORIZATION + "?" + form(params);
    }

    /** {@code application/x-www-form-urlencoded}, también para el canje del código. */
    public static String form(java.util.Map<String, String> params) {
        return params.entrySet().stream()
            .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
    }
}
