package dev.sam.common.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

/**
 * "Entrar con Google" del lado del servidor (REQUERIMIENTOS 5.5, PROTOCOLO.md 5.4): PKCE S256, URL de
 * autorización con solo {@code openid} (RS-OAUTH-01), {@code state} de un solo uso atado a la conexión
 * y a la cuenta (RS-OAUTH-03, RN-22) y validación estricta del ID token (RS-OAUTH-05, RN-23).
 */
class GoogleOidcTest {

    private static final String CLIENT = "123-abc.apps.googleusercontent.com";
    private static final Instant AHORA = Instant.parse("2026-11-07T12:00:00Z");
    private static RSAKey clave;
    private static RSAKey otraClave;

    @BeforeAll
    static void claves() throws Exception {
        clave = new RSAKeyGenerator(2048).keyID("k1").generate();
        otraClave = new RSAKeyGenerator(2048).keyID("k2").generate();
    }

    // ===== PKCE =====

    @Test
    void pkceSigueElVectorDelRfc7636() {
        // RFC 7636, apéndice B
        assertThat(Pkce.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        var pkce = Pkce.create(new SecureRandom());
        assertThat(pkce.verifier()).hasSize(43).matches("[A-Za-z0-9_-]+");
        assertThat(pkce.challenge()).isEqualTo(Pkce.challenge(pkce.verifier()));
        assertThat(Pkce.create(new SecureRandom()).verifier()).isNotEqualTo(pkce.verifier());
    }

    // ===== URL de autorización =====

    @Test
    void laUrlPideSoloOpenidConPkceStateYNonce() {
        var url = GoogleOidc.authorizationUrl(CLIENT, "http://127.0.0.1:53111/", "st", "no", "ch");
        assertThat(url).startsWith("https://accounts.google.com/o/oauth2/v2/auth?");
        var query = parametros(url);
        assertThat(query).containsExactlyInAnyOrderEntriesOf(Map.of("client_id", CLIENT, "redirect_uri", "http://127.0.0.1:53111/",
            "response_type", "code", "scope", "openid", "state", "st", "nonce", "no", "code_challenge", "ch",
            "code_challenge_method", "S256", "prompt", "select_account"));
    }

    static Map<String, String> parametros(String url) {
        var query = new HashMap<String, String>();
        for (var par : URI.create(url).getRawQuery().split("&")) {
            var partes = par.split("=", 2);
            query.put(URLDecoder.decode(partes[0], StandardCharsets.UTF_8), URLDecoder.decode(partes[1], StandardCharsets.UTF_8));
        }
        return query;
    }

    // ===== state =====

    private static final class Reloj extends Clock {
        private Instant ahora = AHORA;

        @Override
        public Instant instant() {
            return ahora;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    @Test
    void elStateEsDeUnSoloUsoYQuedaAtadoALaConexion() {
        var reloj = new Reloj();
        var estados = new OAuthStates(new SecureRandom(), reloj);
        var conexion = new Object();
        var pendiente = estados.issue(conexion, "Steve", OAuthStates.Purpose.LINK, "http://127.0.0.1:1/");
        assertThat(pendiente.state()).hasSize(43).matches("[A-Za-z0-9_-]+");
        assertThat(pendiente.nonce()).hasSize(43).isNotEqualTo(pendiente.state());
        assertThat(pendiente.pkce().challenge()).isEqualTo(Pkce.challenge(pendiente.pkce().verifier()));
        // Otra conexión con el mismo state no lo consume
        assertThat(estados.consume(new Object(), pendiente.state())).isEmpty();
        assertThat(estados.consume(conexion, "otro")).isEmpty();
        var consumido = estados.consume(conexion, pendiente.state());
        assertThat(consumido).contains(pendiente);
        assertThat(consumido.get().nick()).isEqualTo("Steve");
        assertThat(consumido.get().purpose()).isEqualTo(OAuthStates.Purpose.LINK);
        assertThat(consumido.get().redirectUri()).isEqualTo("http://127.0.0.1:1/");
        assertThat(estados.consume(conexion, pendiente.state())).as("un solo uso").isEmpty();
    }

    @Test
    void elStateVenceALosCincoMinutosYUnoNuevoReemplazaAlAnterior() {
        var reloj = new Reloj();
        var estados = new OAuthStates(new SecureRandom(), reloj);
        var conexion = new Object();
        var viejo = estados.issue(conexion, "Steve", OAuthStates.Purpose.LOGIN, "http://127.0.0.1:1/");
        var nuevo = estados.issue(conexion, "Steve", OAuthStates.Purpose.LOGIN, "http://127.0.0.1:2/");
        assertThat(estados.consume(conexion, viejo.state())).as("el nuevo reemplaza al anterior").isEmpty();
        reloj.ahora = AHORA.plus(OAuthStates.TTL);
        assertThat(estados.consume(conexion, nuevo.state())).as("justo al vencer, todavía vale").contains(nuevo);
        var tarde = estados.issue(conexion, "Steve", OAuthStates.Purpose.LOGIN, "http://127.0.0.1:3/");
        reloj.ahora = reloj.ahora.plus(OAuthStates.TTL).plusMillis(1);
        assertThat(estados.consume(conexion, tarde.state())).as("vencido").isEmpty();
        assertThat(OAuthStates.TTL).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void alCerrarseLaConexionSeOlvidaSuState() {
        var estados = new OAuthStates(new SecureRandom(), new Reloj());
        var conexion = new Object();
        var pendiente = estados.issue(conexion, "Steve", OAuthStates.Purpose.LINK, "http://127.0.0.1:1/");
        estados.forget(conexion);
        assertThat(estados.consume(conexion, pendiente.state())).isEmpty();
    }

    // ===== ID token =====

    private static IdTokenValidator validador() {
        return new IdTokenValidator(CLIENT, new ImmutableJWKSet<SecurityContext>(new JWKSet(clave.toPublicJWK())),
            Clock.fixed(AHORA, ZoneOffset.UTC));
    }

    private static JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().issuer("https://accounts.google.com").audience(CLIENT).subject("1098765")
            .issueTime(Date.from(AHORA.minusSeconds(10))).expirationTime(Date.from(AHORA.plusSeconds(3600))).claim("nonce", "n1");
    }

    private static String firmar(JWTClaimsSet claims, RSAKey con) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(con.getKeyID()).type(JOSEObjectType.JWT).build(), claims);
        jwt.sign(new RSASSASigner(con));
        return jwt.serialize();
    }

    @Test
    void unIdTokenValidoEntregaElSub() throws Exception {
        assertThat(validador().validate(firmar(claims().build(), clave), "n1")).contains("1098765");
        // Google también usa el iss sin esquema
        assertThat(validador().validate(firmar(claims().issuer("accounts.google.com").build(), clave), "n1")).contains("1098765");
    }

    @Test
    void cadaAtaqueConocidoSeRechaza() throws Exception {
        var casos = new java.util.LinkedHashMap<String, String>();
        casos.put("nonce ajeno", firmar(claims().build(), clave));
        casos.put("sin nonce", firmar(claims().claim("nonce", null).build(), clave));
        casos.put("aud ajeno", firmar(claims().audience("otro-cliente").build(), clave));
        casos.put("aud con otro más", firmar(claims().audience(List.of(CLIENT, "otro")).build(), clave));
        casos.put("iss ajeno", firmar(claims().issuer("https://evil.example").build(), clave));
        casos.put("vencido", firmar(claims().expirationTime(Date.from(AHORA.minusSeconds(120))).build(), clave));
        casos.put("sin exp", firmar(claims().expirationTime(null).build(), clave));
        casos.put("sin sub", firmar(claims().subject(null).build(), clave));
        casos.put("firmado con otra clave", firmar(claims().build(), otraClave));
        casos.put("alg=none", new PlainJWT(claims().build()).serialize());
        var hs = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims().build());
        var secreto = new byte[32];
        Arrays.fill(secreto, (byte) 1);
        hs.sign(new MACSigner(secreto));
        casos.put("HS256", hs.serialize());
        casos.put("basura", "no.es.un.jwt");
        for (var caso : casos.entrySet()) {
            var nonce = caso.getKey().equals("nonce ajeno") ? "otro" : "n1";
            assertThat(validador().validate(caso.getValue(), nonce)).as(caso.getKey()).isEmpty();
        }
    }

    @Test
    void elValidadorExigeUnClientId() {
        assertThatThrownBy(() -> new IdTokenValidator("", new ImmutableJWKSet<>(new JWKSet()), Clock.systemUTC()))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("falta el client_id de Google");
    }
}
