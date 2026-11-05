package dev.sam.common.identity;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.List;

/**
 * Lista de palabras de la huella visual (PROTOCOLO.md 3.5, P-07).
 *
 * <p>Es el archivo oficial de BIP-39 en español, <b>sin modificar</b> (su SHA-256 se fija en los
 * tests). El archivo viene en NFD; al cargarlo se normaliza a NFC para que la fuente del juego
 * dibuje bien las tildes. El orden es parte del protocolo: no cambia dentro de una versión mayor.
 */
public final class Wordlist {

    public static final String SPANISH_RESOURCE = "/dev/sam/common/identity/bip39-es.txt";
    public static final int SIZE = 2048;

    private static final class Spanish {
        static final List<String> WORDS = load(SPANISH_RESOURCE);
    }

    private Wordlist() {
    }

    public static List<String> spanish() {
        return Spanish.WORDS;
    }

    static List<String> load(String resource) {
        try (var in = Wordlist.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("No se encontró la lista de palabras " + resource);
            }
            return parse(in);
        } catch (IOException e) {
            throw new UncheckedIOException("No se pudo leer la lista de palabras " + resource, e);
        }
    }

    static List<String> parse(InputStream in) throws IOException {
        var words = new String(in.readAllBytes(), StandardCharsets.UTF_8).lines()
            .filter(line -> !line.isEmpty())
            .map(line -> Normalizer.normalize(line, Normalizer.Form.NFC))
            .toList();
        if (words.size() != SIZE) {
            throw new IllegalStateException(
                "La lista de palabras debe tener " + SIZE + " entradas y tiene " + words.size());
        }
        return words;
    }
}
