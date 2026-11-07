package dev.sam.server.auth;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;

import dev.sam.common.oauth.GoogleOidc;
import dev.sam.common.oauth.GoogleTokenClient;
import dev.sam.common.oauth.IdTokenValidator;
import dev.sam.common.oauth.OAuthStates;
import dev.sam.common.proto.account.OAuthCode;

/**
 * "Entrar con Google" en el servidor (REQUERIMIENTOS 5.5): arma la URL de autorización con un
 * {@code state} atado a la conexión, y al volver el código lo canjea y valida el ID token fuera del hilo
 * del servidor. El {@code client_secret} nunca sale de aquí ni aparece en logs (RS-OAUTH-04).
 */
public final class GoogleSignIn {

    public static final String CLIENT_ID = "SAM_OAUTH_GOOGLE_CLIENT_ID";
    public static final String CLIENT_SECRET = "SAM_OAUTH_GOOGLE_CLIENT_SECRET";

    /** El resultado de un flujo: para qué se abrió, de quién, y el {@code sub} si Google lo confirmó. */
    public record Verified(OAuthStates.Pending pending, Optional<String> sub) {
    }

    private final String clientId;
    private final OAuthStates states = new OAuthStates(new SecureRandom(), Clock.systemUTC());
    private final GoogleTokenClient tokens;
    private final IdTokenValidator validator;
    private final ExecutorService work = Executors.newFixedThreadPool(2, runnable -> {
        var thread = new Thread(runnable, "SAM OAuth");
        thread.setDaemon(true);
        return thread;
    });

    private GoogleSignIn(String clientId, String clientSecret) throws IOException {
        this.clientId = clientId;
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.tokens = new GoogleTokenClient(clientId, clientSecret, (url, form) -> {
            var request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build();
            try {
                var response = http.send(request, HttpResponse.BodyHandlers.ofString());
                return new GoogleTokenClient.Response(response.statusCode(), response.body());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrumpido", e);
            }
        });
        // Las claves de Google con caché y reintento (RS-OAUTH-05: rotación de JWKS)
        var keys = JWKSourceBuilder.<SecurityContext>create(URI.create(GoogleOidc.JWKS).toURL()).retrying(true).build();
        this.validator = new IdTokenValidator(clientId, keys, Clock.systemUTC());
    }

    /** Habilitado solo con client_id y client_secret (REQUERIMIENTOS 5.5: sin credenciales, no hay botón). */
    public static Optional<GoogleSignIn> fromConfig(Map<String, String> config) throws IOException {
        var id = config.getOrDefault(CLIENT_ID, "").strip();
        var secret = config.getOrDefault(CLIENT_SECRET, "").strip();
        if (id.isEmpty() || secret.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new GoogleSignIn(id, secret));
    }

    /** Para los logs: el client_id se puede mostrar; el secreto nunca. */
    public String clientId() {
        return clientId;
    }

    /** @return la URL de autorización para el navegador del jugador */
    public String start(Object connection, String nick, OAuthStates.Purpose purpose, int port) {
        var redirect = "http://127.0.0.1:" + port + "/";
        var pending = states.issue(connection, nick, purpose, redirect);
        return GoogleOidc.authorizationUrl(clientId, redirect, pending.state(), pending.nonce(), pending.pkce().challenge());
    }

    /**
     * Cierra el flujo de esta conexión: vacío si el {@code state} no es el suyo o venció; si no, el canje y
     * la validación (el {@code sub} queda vacío si algo falló).
     */
    public CompletableFuture<Optional<Verified>> finish(Object connection, OAuthCode code) {
        var pending = states.consume(connection, code.state());
        if (pending.isEmpty()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        var flow = pending.get();
        return CompletableFuture.supplyAsync(() -> {
            var sub = tokens.exchange(code.code(), flow.pkce().verifier(), flow.redirectUri())
                .flatMap(idToken -> validator.validate(idToken, flow.nonce()));
            return Optional.of(new Verified(flow, sub));
        }, work);
    }

    public void forget(Object connection) {
        states.forget(connection);
    }
}
