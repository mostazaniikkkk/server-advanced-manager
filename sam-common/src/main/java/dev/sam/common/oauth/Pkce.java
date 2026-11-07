package dev.sam.common.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PKCE con S256 (RFC 7636): el {@code verifier} nunca sale del servidor (PROTOCOLO.md 5.4); a Google
 * solo va el {@code challenge}.
 */
public record Pkce(String verifier, String challenge) {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    public static Pkce create(SecureRandom random) {
        var verifier = randomToken(random);
        return new Pkce(verifier, challenge(verifier));
    }

    public static String challenge(String verifier) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return URL.encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 siempre existe en la JDK", e);
        }
    }

    /** 32 bytes aleatorios en base64url: 43 caracteres. */
    static String randomToken(SecureRandom random) {
        var bytes = new byte[32];
        random.nextBytes(bytes);
        return URL.encodeToString(bytes);
    }
}
