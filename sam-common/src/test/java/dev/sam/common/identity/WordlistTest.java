package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

/** Lista de palabras de la huella (P-07): BIP-39 en español, sin modificar. */
class WordlistTest {

    /** SHA-256 del archivo oficial (github.com/bitcoin/bips, bip-0039/spanish.txt). */
    private static final String OFFICIAL_SHA256 = "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b";

    @Test
    void elRecursoEsElArchivoOficialSinModificar() throws Exception {
        try (var in = Wordlist.class.getResourceAsStream(Wordlist.SPANISH_RESOURCE)) {
            assertThat(in).isNotNull();
            var hash = MessageDigest.getInstance("SHA-256").digest(in.readAllBytes());
            assertThat(HexFormat.of().formatHex(hash)).isEqualTo(OFFICIAL_SHA256);
        }
    }

    @Test
    void tiene2048PalabrasUnicas() {
        var palabras = Wordlist.spanish();
        assertThat(palabras).hasSize(2048).doesNotHaveDuplicates();
    }

    @Test
    void conservaElOrdenOficial() {
        var palabras = Wordlist.spanish();
        assertThat(palabras.get(0)).isEqualTo("ábaco");
        assertThat(palabras.get(1)).isEqualTo("abdomen");
        assertThat(palabras.get(2047)).isEqualTo("zurdo");
    }

    @Test
    void lasPalabrasQuedanEnNfcParaQueLaFuenteDelJuegoLasDibujeBien() {
        // El archivo oficial está en NFD (tildes como caracteres combinantes)
        assertThat(Wordlist.spanish()).allMatch(p -> Normalizer.isNormalized(p, Normalizer.Form.NFC));
        assertThat(Wordlist.spanish().get(0)).hasSize(5);
    }

    @Test
    void lasPrimerasCuatroLetrasIdentificanCadaPalabra() {
        var prefijos = Wordlist.spanish().stream()
            .map(p -> p.substring(0, Math.min(4, p.length())))
            .collect(Collectors.toCollection(HashSet::new));
        assertThat(prefijos).hasSize(2048);
    }

    @Test
    void laListaEsInmutable() {
        assertThatThrownBy(() -> Wordlist.spanish().set(0, "x"))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    // ===== parse y load directos: spanish() está cacheada y no ejercita estos caminos en cada test =====

    @Test
    void loadDelRecursoOficialDevuelveLaListaCompleta() {
        var palabras = Wordlist.load(Wordlist.SPANISH_RESOURCE);
        assertThat(palabras).hasSize(2048).startsWith("ábaco", "abdomen").endsWith("zurdo");
    }

    @Test
    void parseIgnoraLineasVaciasYAceptaFinDeLineaWindows() throws Exception {
        var texto = new StringBuilder("\n");
        for (int i = 0; i < 2048; i++) {
            texto.append("palabra").append(i).append(i % 2 == 0 ? "\r\n" : "\n\n");
        }
        var palabras = Wordlist.parse(new ByteArrayInputStream(texto.toString().getBytes(StandardCharsets.UTF_8)));
        assertThat(palabras).hasSize(2048).startsWith("palabra0", "palabra1").endsWith("palabra2047");
    }

    @Test
    void parseNormalizaCadaPalabraANfc() throws Exception {
        var texto = new StringBuilder("ábaco\n");  // "ábaco" en NFD
        for (int i = 1; i < 2048; i++) {
            texto.append("p").append(i).append('\n');
        }
        var palabras = Wordlist.parse(new ByteArrayInputStream(texto.toString().getBytes(StandardCharsets.UTF_8)));
        assertThat(palabras.get(0)).isEqualTo("ábaco").hasSize(5);
    }

    @Test
    void unaListaConOtraCantidadDePalabrasSeRechaza() {
        var corta = "uno\ndos\n".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> Wordlist.parse(new ByteArrayInputStream(corta)))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("2048");
    }

    @Test
    void unRecursoInexistenteSeRechaza() {
        assertThatThrownBy(() -> Wordlist.load("/no/existe.txt"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("/no/existe.txt");
    }
}
