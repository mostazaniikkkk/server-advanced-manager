package dev.sam.common.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

/**
 * El canje del código en Google (REQUERIMIENTOS 5.5, paso 5) y el redirect que llega al loopback del
 * cliente (paso 4). El {@code client_secret} solo viaja a Google (RS-OAUTH-04).
 */
class GoogleTokenClientTest {

    private record Llamada(String url, String cuerpo) {
    }

    private final List<Llamada> llamadas = new ArrayList<>();

    private GoogleTokenClient cliente(int estado, String respuesta) {
        return new GoogleTokenClient("cid", "secreto-xyz", (url, cuerpo) -> {
            llamadas.add(new Llamada(url, cuerpo));
            return new GoogleTokenClient.Response(estado, respuesta);
        });
    }

    @Test
    void elCanjeEnviaElCodigoElVerifierYElSecretoSoloAGoogle() {
        var cliente = cliente(200, "{\"access_token\":\"a\",\"id_token\":\"eyJ.x.y\",\"token_type\":\"Bearer\"}");
        assertThat(cliente.exchange("4/código", "verif", "http://127.0.0.1:5000/")).contains("eyJ.x.y");
        assertThat(llamadas).hasSize(1);
        assertThat(llamadas.getFirst().url()).isEqualTo("https://oauth2.googleapis.com/token");
        assertThat(GoogleOidcTest.parametros("https://x/?" + llamadas.getFirst().cuerpo())).containsExactlyInAnyOrderEntriesOf(Map.of(
            "grant_type", "authorization_code", "code", "4/código", "client_id", "cid", "client_secret", "secreto-xyz",
            "redirect_uri", "http://127.0.0.1:5000/", "code_verifier", "verif"));
        assertThat(cliente.toString()).doesNotContain("secreto-xyz").contains("cid");
    }

    @Test
    void sinIdTokenOConErrorNoHayToken() {
        assertThat(cliente(400, "{\"error\":\"invalid_grant\"}").exchange("c", "v", "r")).isEmpty();
        assertThat(cliente(200, "{\"access_token\":\"a\"}").exchange("c", "v", "r")).isEmpty();
        assertThat(cliente(200, "{\"id_token\":5}").exchange("c", "v", "r")).isEmpty();
        assertThat(cliente(200, "no es json").exchange("c", "v", "r")).isEmpty();
        assertThat(cliente(200, "[]").exchange("c", "v", "r")).isEmpty();
        assertThat(cliente(299, "{\"id_token\":\"t\"}").exchange("c", "v", "r")).contains("t");
        assertThat(cliente(300, "{\"id_token\":\"t\"}").exchange("c", "v", "r")).isEmpty();
        assertThat(cliente(199, "{\"id_token\":\"t\"}").exchange("c", "v", "r")).isEmpty();
        var falla = new GoogleTokenClient("cid", "s", (url, cuerpo) -> {
            throw new java.io.IOException("sin red");
        });
        assertThat(falla.exchange("c", "v", "r")).isEmpty();
    }

    @Test
    void elRedirectDelLoopbackEntregaElCodigoSoloConElStateCorrecto() {
        assertThat(LoopbackRedirect.code("/?state=abc&code=4%2F0Ab-c&scope=openid", "abc")).contains("4/0Ab-c");
        assertThat(LoopbackRedirect.code("/?code=4%2F0Ab&state=abc", "abc")).contains("4/0Ab");
        assertThat(LoopbackRedirect.code("/?code=x&state=otro", "abc")).isEmpty();
        assertThat(LoopbackRedirect.code("/?code=x", "abc")).isEmpty();
        assertThat(LoopbackRedirect.code("/?state=abc", "abc")).isEmpty();
        assertThat(LoopbackRedirect.code("/?state=abc&code=", "abc")).isEmpty();
        assertThat(LoopbackRedirect.code("/?error=access_denied&state=abc", "abc")).isEmpty();
        assertThat(LoopbackRedirect.code("/?state=abc&code=x&error=access_denied", "abc")).as("error con código").isEmpty();
        assertThat(LoopbackRedirect.code("/", "abc")).isEmpty();
        assertThat(LoopbackRedirect.code("/?state=abc&code=x&code=y", "abc")).as("repetido").isEmpty();
        assertThat(LoopbackRedirect.code("/?=&state=abc&code=x&raro", "abc")).contains("x");
        assertThat(LoopbackRedirect.code("/otra?state=abc&code=x", "abc")).as("otra ruta").isEmpty();
        assertThat(LoopbackRedirect.code("?state=abc&code=x", "abc")).as("sin ruta").isEmpty();
        assertThat(LoopbackRedirect.code("/?=&=&state=abc&code=x", "abc")).as("clave vacía repetida").isEmpty();
    }

    @Test
    void elStateEsperadoSeLeeDeLaUrlQueSeAbre() {
        assertThat(LoopbackRedirect.stateOf("https://accounts.google.com/o/oauth2/v2/auth?client_id=c&state=s%2Bt&nonce=n")).contains("s+t");
        assertThat(LoopbackRedirect.stateOf("https://accounts.google.com/o/oauth2/v2/auth?client_id=c")).isEqualTo(Optional.empty());
        assertThat(LoopbackRedirect.stateOf("https://accounts.google.com/")).isEmpty();
        assertThat(LoopbackRedirect.stateOf("https://a/?state=x&state=y")).as("repetido").isEmpty();
    }
}
