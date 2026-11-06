package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/**
 * signature.json (PROTOCOLO.md 8.2), con lectura estricta: es un archivo de seguridad, así que
 * nada de claves duplicadas (un lector podría quedarse con la primera y otro con la última),
 * escapes, claves desconocidas ni codificaciones alternativas.
 */
class ScriptSignatureTest {

    /** Vector de referencia: lockfile del ciclo 8 firmado con K1 (RFC 8032), con 'cryptography' de Python. */
    static final String VECTOR = "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\","
        + "\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\","
        + "\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}\n";

    @Test
    void leeElVectorDeReferencia() {
        var firma = ScriptSignature.parse(utf8(VECTOR));
        assertThat(firma.keyId()).isEqualTo(KeyId.of("21fe31dfa154a261"));
        assertThat(HexFormat.of().formatHex(firma.lockSha256()))
            .isEqualTo("e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d");
        assertThat(firma.signature()).hasSize(64);
    }

    @Test
    void escribeExactamenteElFormatoCanonico() {
        assertThat(new String(ScriptSignature.parse(utf8(VECTOR)).toJson(), StandardCharsets.UTF_8)).isEqualTo(VECTOR);
    }

    @Test
    void aceptaEspaciosYOtroOrdenDeClaves() {
        var formateado = """
            {
              "signature" : "3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==",
              "lock_sha256":"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d",
            \t"key_id": "21fe31dfa154a261",
              "format": "sam-sig-v1"
            }
            """;
        assertThat(ScriptSignature.parse(utf8(formateado))).isEqualTo(ScriptSignature.parse(utf8(VECTOR)));
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {
        "",
        "[]",
        "{}",
        "null",
        // clave duplicada: el ataque clásico de "cada lector ve otra firma"
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"key_id\":\"39f713d0a644253f\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}",
        // clave desconocida
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\",\"extra\":\"x\"}",
        // falta una clave
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\"}",
        // formato desconocido
        "{\"format\":\"sam-sig-v2\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}",
        // hex en mayúsculas
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21FE31DFA154A261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}",
        // lock_sha256 corto
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67b\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}",
        // firma de 63 bytes
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7\"}",
        // base64 no canónico (bits de relleno distintos de cero: "Aw==" → "Ax==")
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Ax==\"}",
        // escapes
        "{\"form\\u0061t\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}",
        // valor que no es string
        "{\"format\":1,\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}",
        // basura al final
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\"}x",
        // coma final
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\",}",
        // caracteres no ASCII
        "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"3LVXhNjtUBJ6g2kmsCTjBda7+iNyk6Id/pHFIN6dTuUDjhaPy9RpeyRrG0CEniaqjYCvYXnskdxox4cKv6t7Aw==\",\"ñ\":\"x\"}",
    })
    void rechazaDocumentosInvalidos(String json) {
        assertThatThrownBy(() -> ScriptSignature.parse(utf8(json)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("signature.json");
    }

    @Test
    void unaFirmaQueNoEsBase64SeRechazaConSuMotivo() {
        var json = "{\"format\":\"sam-sig-v1\",\"key_id\":\"21fe31dfa154a261\",\"lock_sha256\":"
            + "\"e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d\",\"signature\":\"@@@@\"}";
        assertThatThrownBy(() -> ScriptSignature.parse(utf8(json)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("signature no es base64");
    }

    @ParameterizedTest(name = "rechaza el carácter U+{0}")
    @ValueSource(strings = {"000C", "000B", "0000", "007F", "00A0"})
    void soloAceptaElEspacioEnBlancoDeJsonEntreTokens(String codigo) {
        // \f y \x0B los acepta el \s de Java pero no JSON: aceptarlos sería un diferencial con otros lectores
        var c = (char) Integer.parseInt(codigo, 16);
        var conCaracter = VECTOR.replace("\",\"key_id\"", "\"," + c + "\"key_id\"");
        assertThatThrownBy(() -> ScriptSignature.parse(conCaracter.getBytes(StandardCharsets.ISO_8859_1)))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rechazaCaracteresDeControlDentroDeUnValor() {
        var conControl = VECTOR.replace("sam-sig-v1", "sam-sig-v1\u0001");
        assertThatThrownBy(() -> ScriptSignature.parse(utf8(conControl))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rechazaDocumentosDeMasDe512Bytes() {
        var conRelleno = VECTOR.replace("{", "{" + " ".repeat(512 - VECTOR.length()));
        assertThat(utf8(conRelleno)).hasSize(512);
        assertThat(ScriptSignature.parse(utf8(conRelleno))).isEqualTo(ScriptSignature.parse(utf8(VECTOR)));
        assertThatThrownBy(() -> ScriptSignature.parse(utf8(" " + conRelleno)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("512");
    }

    @Test
    void validaLasLongitudesAlConstruir() {
        assertThatThrownBy(() -> new ScriptSignature(KeyId.of("21fe31dfa154a261"), new byte[31], new byte[64]))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ScriptSignature(KeyId.of("21fe31dfa154a261"), new byte[32], new byte[63]))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void esInmutableYSeComparaPorValor() {
        var a = ScriptSignature.parse(utf8(VECTOR));
        a.lockSha256()[0] ^= 1;
        a.signature()[0] ^= 1;
        assertThat(a).isEqualTo(ScriptSignature.parse(utf8(VECTOR))).hasSameHashCodeAs(ScriptSignature.parse(utf8(VECTOR)));
        var otroLock = new ScriptSignature(a.keyId(), new byte[32], a.signature());
        var otraFirma = new ScriptSignature(a.keyId(), a.lockSha256(), new byte[64]);
        var otraClave = new ScriptSignature(KeyId.of("39f713d0a644253f"), a.lockSha256(), a.signature());
        for (var distinta : java.util.List.of(otroLock, otraFirma, otraClave)) {
            assertThat(distinta).isNotEqualTo(a);
            assertThat(distinta.hashCode()).isNotEqualTo(a.hashCode());
        }
        assertThat((Object) a).isNotEqualTo("x");
        assertThat(a.toString()).contains("21fe31dfa154a261");
    }

    @Property
    void escribirYLeerEsIdaYVuelta(@ForAll @Size(8) byte[] id, @ForAll @Size(32) byte[] lock, @ForAll @Size(64) byte[] firma) {
        var original = new ScriptSignature(KeyId.of(HexFormat.of().formatHex(id)), lock, firma);
        var json = original.toJson();
        assertThat(ScriptSignature.parse(json)).isEqualTo(original);
        assertThat(new String(json, StandardCharsets.UTF_8))
            .contains("\"signature\":\"" + Base64.getEncoder().encodeToString(firma) + "\"");
    }

    static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
