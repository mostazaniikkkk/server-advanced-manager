package dev.sam.common.oauth;

import java.time.Clock;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Validación del ID token de Google (RS-OAUTH-05, RN-23): solo RS256 con las claves de Google, iss de
 * Google, aud exactamente nuestro client_id, exp vigente y el nonce de este flujo. Cualquier otra cosa
 * se rechaza sin decir por qué.
 */
public final class IdTokenValidator {

    private static final Set<String> ISSUERS = Set.of("https://accounts.google.com", "accounts.google.com");

    private final String clientId;
    private final JWKSource<SecurityContext> keys;
    private final Clock clock;

    public IdTokenValidator(String clientId, JWKSource<SecurityContext> keys, Clock clock) {
        if (clientId.isEmpty()) {
            throw new IllegalArgumentException("falta el client_id de Google");
        }
        this.clientId = clientId;
        this.keys = keys;
        this.clock = clock;
    }

    /** @return el {@code sub} de la cuenta de Google, o vacío si el token no es válido */
    public Optional<String> validate(String idToken, String expectedNonce) {
        var processor = new DefaultJWTProcessor<SecurityContext>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keys));
        var exact = new JWTClaimsSet.Builder().audience(clientId).claim("nonce", expectedNonce).build();
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(exact, Set.of("iss", "sub", "exp", "iat")) {
            @Override
            protected Date currentTime() {
                return Date.from(clock.instant());
            }
        });
        try {
            var claims = processor.process(idToken, null);
            if (!ISSUERS.contains(claims.getIssuer())) {
                return Optional.empty();
            }
            return Optional.of(claims.getSubject());
        } catch (java.text.ParseException | com.nimbusds.jose.proc.BadJOSEException | com.nimbusds.jose.JOSEException e) {
            return Optional.empty();
        }
    }
}
