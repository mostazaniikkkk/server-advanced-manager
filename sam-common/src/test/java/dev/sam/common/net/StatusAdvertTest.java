package dev.sam.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonParser;

import dev.sam.common.identity.ServerId;

/** El campo sam del estado (PROTOCOLO.md 2.4): el servidor lo agrega y el cliente lo lee estricto. */
class StatusAdvertTest {

    private static final String ID = "45f6c09d17e093f73d707e48bed9de34";
    private static final String ESTADO = "{\"description\":{\"text\":\"SAM QA\"},\"version\":{\"name\":\"1.21.1\",\"protocol\":767}}";

    @Test
    void elServidorAgregaElCampoSamSinTocarElRestoNiPublicarLaRutaWebSocket() {
        var json = JsonParser.parseString(ESTADO);
        var texto = StatusAdvert.render(json, Optional.of(new StatusAdvert(ServerId.fromHex(ID))));
        assertThat(JsonParser.parseString(texto)).isEqualTo(JsonParser.parseString(
            "{\"description\":{\"text\":\"SAM QA\"},\"version\":{\"name\":\"1.21.1\",\"protocol\":767},"
                + "\"sam\":{\"v\":\"1.0\",\"id\":\"" + ID + "\",\"tls\":true}}"));
        assertThat(texto).doesNotContain("\"ws\"");
        // El original no se modifica: se puede volver a usar
        assertThat(json).isEqualTo(JsonParser.parseString(ESTADO));
    }

    @Test
    void sinAnuncioElEstadoQuedaIgual() {
        assertThat(JsonParser.parseString(StatusAdvert.render(JsonParser.parseString(ESTADO), Optional.empty())))
            .isEqualTo(JsonParser.parseString(ESTADO));
        assertThat(StatusAdvert.render(JsonParser.parseString("\"raro\""), Optional.of(new StatusAdvert(ServerId.fromHex(ID)))))
            .isEqualTo("\"raro\"");
    }

    @Test
    void elClienteLeeLoQueElServidorAnuncia() {
        var anuncio = new StatusAdvert(ServerId.fromHex(ID));
        var texto = StatusAdvert.render(JsonParser.parseString(ESTADO), Optional.of(anuncio));
        assertThat(StatusAdvert.read(JsonParser.parseString(texto))).contains(anuncio);
        // Otra versión menor sigue siendo SAM
        assertThat(StatusAdvert.read(JsonParser.parseString("{\"sam\":{\"v\":\"1.7\",\"id\":\"" + ID + "\",\"tls\":true}}")))
            .contains(anuncio);
    }

    @Test
    void unEstadoSinSamOConUnSamInvalidoNoEsSam() {
        var invalidos = List.of(ESTADO, "\"texto\"", "{\"sam\":1}", "{\"sam\":{}}",
            "{\"sam\":{\"v\":\"1.0\",\"id\":\"" + ID + "\"}}",
            "{\"sam\":{\"v\":\"1.0\",\"id\":\"" + ID + "\",\"tls\":false}}",
            "{\"sam\":{\"v\":\"1.0\",\"id\":\"" + ID + "\",\"tls\":\"true\"}}",
            "{\"sam\":{\"v\":\"1.0\",\"id\":\"zz\",\"tls\":true}}",
            "{\"sam\":{\"v\":\"1.0\",\"id\":7,\"tls\":true}}",
            "{\"sam\":{\"id\":\"" + ID + "\",\"tls\":true}}",
            "{\"sam\":{\"v\":1,\"id\":\"" + ID + "\",\"tls\":true}}",
            // Número y no texto, aunque se lea igual
            "{\"sam\":{\"v\":1.0,\"id\":\"" + ID + "\",\"tls\":true}}",
            "{\"sam\":{\"v\":\"uno\",\"id\":\"" + ID + "\",\"tls\":true}}",
            "{\"sam\":{\"v\":\"1.0.0\",\"id\":\"" + ID + "\",\"tls\":true}}",
            "{\"sam\":{\"v\":\"1.0\",\"id\":\"" + ID + "00\",\"tls\":true}}");
        for (var estado : invalidos) {
            assertThat(StatusAdvert.read(JsonParser.parseString(estado))).as(estado).isEmpty();
        }
    }
}
