package dev.sam.common.identity;

import static dev.sam.common.identity.TestKeys.K1;
import static dev.sam.common.identity.TestKeys.K2;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import dev.sam.common.net.ServerAddress;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;

/**
 * Persistencia del almacén de pins en {@code config/sam-client/pins.json} (PROTOCOLO.md 3.3).
 *
 * <p>Regla de seguridad: un archivo dañado o manipulado nunca debilita la protección. Lo
 * inválido se descarta (ese servidor vuelve a primera conexión) y se informa como problema.
 */
class PinStoreJsonTest {

    private static final ServerId ID_A = ServerId.fromHex("00000000000000000000000000000001");
    private static final ServerId ID_B = ServerId.fromHex("00000000000000000000000000000002");
    private static final ServerAddress DIR_TCP = ServerAddress.parse("play.ejemplo.com:25565");
    private static final ServerAddress DIR_WS = ServerAddress.parse("wss://mc.ejemplo.com/a1b2c3");
    private static final ServerAddress DIR_B = ServerAddress.parse("otro.ejemplo.com");
    private static final Instant T0 = Instant.parse("2026-11-04T18:00:00Z");
    private static final Instant T1 = Instant.parse("2026-12-01T10:30:00Z");

    private static final String SPKI_K1 = Base64.getEncoder().encodeToString(K1.spki());
    private static final String SPKI_K2 = Base64.getEncoder().encodeToString(K2.spki());
    private static final String PIN_K1 = K1.publicKey().pin().hex();
    private static final String PIN_K2 = K2.publicKey().pin().hex();

    // ===== Escritura =====

    @Test
    void unAlmacenVacioSeEscribeAsi() {
        assertThat(PinStoreJson.encode(PinStore.empty())).isEqualTo("""
            {
              "version": 1,
              "servers": {},
              "addresses": {}
            }
            """);
    }

    @Test
    void laEscrituraEsDeterministaYOrdenada() {
        assertThat(PinStoreJson.encode(ejemplo())).isEqualTo(ejemploJson());
    }

    @Test
    void elOrdenDeConstruccionNoCambiaElArchivo() {
        var alReves = PinStore.empty()
            .trust(DIR_B, ID_B, K2.publicKey(), "Servidor B", T1)
            .trust(DIR_WS, ID_A, K1.publicKey(), "Mi Servidor", T0)
            .addAddress(DIR_TCP, ID_A);
        assertThat(PinStoreJson.encode(alReves)).isEqualTo(ejemploJson());
    }

    // ===== Lectura =====

    @Test
    void leerLoEscritoDevuelveElMismoAlmacenSinProblemas() {
        var resultado = PinStoreJson.decode(ejemploJson());
        assertThat(resultado.problems()).isEmpty();
        assertThat(resultado.store()).isEqualTo(ejemplo());
    }

    @Test
    void aceptaOtroFormatoDeEspaciosYOrdenDeCampos() {
        var compacto = "{\"addresses\":{\"otro.ejemplo.com\":\"" + ID_B.hex() + "\"},\"servers\":{\"" + ID_B.hex()
            + "\":{\"name\":\"Servidor B\",\"first_seen\":\"2026-12-01T10:30:00Z\",\"spki\":\"" + SPKI_K2
            + "\",\"pin\":\"" + PIN_K2 + "\"}},\"version\":1}";
        var resultado = PinStoreJson.decode(compacto);
        assertThat(resultado.problems()).isEmpty();
        assertThat(resultado.store()).isEqualTo(PinStore.empty().trust(DIR_B, ID_B, K2.publicKey(), "Servidor B", T1));
    }

    @Test
    void ignoraCamposDesconocidosParaCompatibilidadFutura() {
        var conExtras = ejemploJson()
            .replace("\"version\": 1,", "\"version\": 1,\n  \"futuro\": {\"x\": [1, 2]},")
            .replace("\"name\": \"Mi Servidor\"", "\"name\": \"Mi Servidor\",\n      \"nota\": \"x\"");
        var resultado = PinStoreJson.decode(conExtras);
        assertThat(resultado.problems()).isEmpty();
        assertThat(resultado.store()).isEqualTo(ejemplo());
    }

    // ===== Archivo ilegible o de otra versión: almacén vacío + problema =====

    @Test
    void elAlmacenVacioNoEsIgualAUnoConServidores() {
        // Sin esto, los tests que esperan "almacén vacío" no distinguirían un almacén vacío de uno lleno
        assertThat(ejemplo()).isNotEqualTo(PinStore.empty());
        assertThat(PinStoreJson.decode(ejemploJson()).store()).isNotEqualTo(PinStore.empty());
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {
        "",
        "no es json",
        "{} {}",
        "[]",
        "{\"version\": 1, \"servers\": {}, \"addresses\": {}",       // sin cerrar
        "{\"version\": 1, \"servers\": {}, \"addresses\": {}} x",    // basura al final
        "{\"version\": 1, \"servers\": {}, \"addresses\": {}, }",    // coma final
        "// comentario\n{\"version\": 1, \"servers\": {}, \"addresses\": {}}",
        "{version: 1, \"servers\": {}, \"addresses\": {}}",          // clave sin comillas
        "{\"servers\": {}, \"addresses\": {}}",                      // sin versión
        "{\"version\": 2, \"servers\": {}, \"addresses\": {}}",      // versión desconocida
        "{\"version\": \"1\", \"servers\": {}, \"addresses\": {}}",
        "{\"version\": 1, \"servers\": [], \"addresses\": {}}",
        "{\"version\": 1, \"version\": 1, \"servers\": {}, \"addresses\": {}}",
    })
    void unArchivoIlegibleDaUnAlmacenVacioYUnProblema(String json) {
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store()).isEqualTo(PinStore.empty());
        assertThat(resultado.problems()).hasSize(1).first().asString().contains("pins.json");
    }

    // ===== Entradas inválidas: se descartan solas =====

    @Test
    void unPinQueNoCoincideConSuClaveSeDescartaConSusDirecciones() {
        // Manipulación: alguien cambió la clave pero no el pin (o al revés)
        var manipulado = ejemploJson().replace("\"spki\": \"" + SPKI_K1 + "\"", "\"spki\": \"" + SPKI_K2 + "\"");
        var resultado = PinStoreJson.decode(manipulado);
        assertThat(resultado.store().server(ID_A)).isEmpty();
        assertThat(resultado.store().isPinned(DIR_TCP)).isFalse();
        assertThat(resultado.store().isPinned(DIR_WS)).isFalse();
        assertThat(resultado.store().server(ID_B)).isPresent();
        assertThat(resultado.store().isPinned(DIR_B)).isTrue();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains(ID_A.hex()).contains("pin"));
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {
        "\"spki\": \"no-es-base64!!\"",
        "\"spki\": \"AAAA\"",
        "\"pin\": \"06e3\"",
        "\"first_seen\": \"ayer\"",
        "\"name\": \"\"",
        "\"first_seen\": 5",
    })
    void unaEntradaDeServidorInvalidaSeDescartaSola(String reemplazo) {
        var campo = reemplazo.substring(0, reemplazo.indexOf(':'));
        var json = ejemploJson().replaceFirst(campo + ": (\"[^\"]*\"|[0-9]+)", java.util.regex.Matcher.quoteReplacement(reemplazo));
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().server(ID_A)).isEmpty();
        assertThat(resultado.store().server(ID_B)).isPresent();
        assertThat(resultado.problems()).isNotEmpty().allSatisfy(p -> assertThat(p).contains(ID_A.hex()));
    }

    @Test
    void unNombreDeMasDe64CaracteresSeDescarta() {
        var json = ejemploJson().replace("\"Mi Servidor\"", "\"" + "x".repeat(65) + "\"");
        assertThat(PinStoreJson.decode(json).store().server(ID_A)).isEmpty();
    }

    @Test
    void faltaUnCampoObligatorio() {
        var json = ejemploJson().replace("\"name\": \"Mi Servidor\"", "\"otro\": \"x\"");
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().server(ID_A)).isEmpty();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains(ID_A.hex()));
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"\"x\"", "7", "true", "null", "[1, {\"a\": 2}]"})
    void unaEntradaQueNoEsObjetoSeDescartaSinAfectarALasDemas(String valor) {
        var json = "{\"version\": 1, \"servers\": {\"" + ID_A.hex() + "\": " + valor + ", "
            + servidor(ID_B, PIN_K2, SPKI_K2, "2026-12-01T10:30:00Z", "Servidor B") + "}, \"addresses\": {}}";
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().server(ID_A)).isEmpty();
        assertThat(resultado.store().server(ID_B)).isPresent();
        assertThat(resultado.problems()).hasSize(1).first().asString().startsWith("Servidor " + ID_A.hex());
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"true", "null", "{}", "[\"Mi Servidor\"]", "12"})
    void unCampoQueNoEsStringDescartaSoloSuEntrada(String valor) {
        var json = ejemploJson().replace("\"name\": \"Mi Servidor\"", "\"name\": " + valor);
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().server(ID_A)).isEmpty();
        assertThat(resultado.store().server(ID_B)).isPresent();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).startsWith("Servidor " + ID_A.hex()));
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = {"true", "null", "{}", "[]"})
    void unaDireccionConValorNoStringSeDescartaSola(String valor) {
        var json = ejemploJson().replace("\"otro.ejemplo.com\": \"" + ID_B.hex() + "\"", "\"otro.ejemplo.com\": " + valor);
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().isPinned(DIR_B)).isFalse();
        assertThat(resultado.store().isPinned(DIR_TCP)).isTrue();
        assertThat(resultado.problems()).hasSize(1).first().asString().startsWith("Dirección otro.ejemplo.com");
    }

    @Test
    void unServerIdInvalidoSeDescarta() {
        var json = ejemploJson().replace("\"" + ID_B.hex() + "\": {", "\"zz\": {");
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().server(ID_B)).isEmpty();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains("zz"));
    }

    @Test
    void unServerIdDuplicadoDescartaAmbasEntradasPorAmbiguas() {
        var bloqueA = servidor(ID_A, PIN_K1, SPKI_K1, "2026-11-04T18:00:00Z", "Mi Servidor");
        var bloqueA2 = servidor(ID_A, PIN_K2, SPKI_K2, "2026-11-04T18:00:00Z", "Impostor");
        var json = "{\"version\": 1, \"servers\": {" + bloqueA + "," + bloqueA2 + "}, \"addresses\": {\""
            + DIR_TCP.canonical() + "\": \"" + ID_A.hex() + "\"}}";
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store()).isEqualTo(PinStore.empty());
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains(ID_A.hex()).contains("duplicad"));
    }

    @Test
    void unCampoDuplicadoDentroDeUnaEntradaLaDescarta() {
        var json = ejemploJson().replace("\"name\": \"Mi Servidor\"", "\"name\": \"Mi Servidor\",\n      \"name\": \"Otro\"");
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().server(ID_A)).isEmpty();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains(ID_A.hex()));
    }

    // ===== Direcciones inválidas =====

    @Test
    void unaDireccionNoCanonicaSeDescarta() {
        // Nosotros siempre escribimos la forma canónica: otra forma es una edición a mano o manipulación
        var json = ejemploJson().replace("\"play.ejemplo.com:25565\"", "\"Play.Ejemplo.com:25565\"");
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().isPinned(DIR_TCP)).isFalse();
        assertThat(resultado.store().isPinned(DIR_WS)).isTrue();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains("Play.Ejemplo.com:25565"));
    }

    @Test
    void unaDireccionIlegibleSeDescarta() {
        var json = ejemploJson().replace("\"play.ejemplo.com:25565\"", "\"http://x\"");
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().isPinned(DIR_TCP)).isFalse();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains("http://x"));
    }

    @Test
    void unaDireccionHaciaUnServidorDesconocidoSeDescarta() {
        var json = ejemploJson().replace("\"otro.ejemplo.com\": \"" + ID_B.hex() + "\"",
            "\"otro.ejemplo.com\": \"" + "f".repeat(32) + "\"");
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.store().isPinned(DIR_B)).isFalse();
        assertThat(resultado.store().server(ID_B)).isPresent();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains("otro.ejemplo.com"));
    }

    @Test
    void unaDireccionConValorInvalidoODuplicadaSeDescarta() {
        var noString = ejemploJson().replace("\"otro.ejemplo.com\": \"" + ID_B.hex() + "\"", "\"otro.ejemplo.com\": 7");
        assertThat(PinStoreJson.decode(noString).store().isPinned(DIR_B)).isFalse();

        var duplicada = ejemploJson().replace("\"otro.ejemplo.com\": \"" + ID_B.hex() + "\"",
            "\"otro.ejemplo.com\": \"" + ID_B.hex() + "\",\n    \"otro.ejemplo.com\": \"" + ID_A.hex() + "\"");
        var resultado = PinStoreJson.decode(duplicada);
        assertThat(resultado.store().isPinned(DIR_B)).isFalse();
        assertThat(resultado.problems()).anySatisfy(p -> assertThat(p).contains("otro.ejemplo.com").contains("duplicad"));
    }

    @Test
    void unServidorSinDireccionesSeConservaYSeEscribeIgual() {
        var json = ejemploJson().replace("    \"otro.ejemplo.com\": \"" + ID_B.hex() + "\",\n", "");
        var resultado = PinStoreJson.decode(json);
        assertThat(resultado.problems()).isEmpty();
        assertThat(resultado.store().server(ID_B)).isPresent();
        assertThat(PinStoreJson.decode(PinStoreJson.encode(resultado.store())).store()).isEqualTo(resultado.store());
    }

    // ===== Validación del nombre en el modelo =====

    @Test
    void elNombreDeUnServidorFijadoSeValida() {
        assertThatThrownBy(() -> new PinnedServer(ID_A, K1.publicKey(), "", T0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, K1.publicKey(), "x".repeat(65), T0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PinnedServer(ID_A, K1.publicKey(), "a\nb", T0)).isInstanceOf(IllegalArgumentException.class);
        assertThat(new PinnedServer(ID_A, K1.publicKey(), "x".repeat(64), T0).name()).hasSize(64);
        assertThat(new PinnedServer(ID_A, K1.publicKey(), "Mundo Ñandú ⚔", T0).name()).isEqualTo("Mundo Ñandú ⚔");
    }

    // ===== Propiedad =====

    @Property(tries = 100)
    void escribirYLeerEsIdaYVuelta(@ForAll @Size(32) byte[] semilla, @ForAll @Size(16) byte[] id,
            @ForAll @IntRange(min = 1, max = 65535) int puerto, @ForAll @IntRange(max = 2_000_000_000) int segundos) {
        var store = PinStore.empty().trust(ServerAddress.parse("h.net:" + puerto), ServerId.of(id),
            TestKeys.fromSeed(semilla).publicKey(), "S \"citado\" \\ ñ", Instant.ofEpochSecond(segundos));
        var resultado = PinStoreJson.decode(PinStoreJson.encode(store));
        assertThat(resultado.problems()).isEmpty();
        assertThat(resultado.store()).isEqualTo(store);
    }

    // ===== Datos de ejemplo =====

    private static PinStore ejemplo() {
        return PinStore.empty()
            .trust(DIR_TCP, ID_A, K1.publicKey(), "Mi Servidor", T0)
            .addAddress(DIR_WS, ID_A)
            .trust(DIR_B, ID_B, K2.publicKey(), "Servidor B", T1);
    }

    private static String ejemploJson() {
        return "{\n"
            + "  \"version\": 1,\n"
            + "  \"servers\": {\n"
            + "    \"" + ID_A.hex() + "\": {\n"
            + "      \"pin\": \"" + PIN_K1 + "\",\n"
            + "      \"spki\": \"" + SPKI_K1 + "\",\n"
            + "      \"first_seen\": \"2026-11-04T18:00:00Z\",\n"
            + "      \"name\": \"Mi Servidor\"\n"
            + "    },\n"
            + "    \"" + ID_B.hex() + "\": {\n"
            + "      \"pin\": \"" + PIN_K2 + "\",\n"
            + "      \"spki\": \"" + SPKI_K2 + "\",\n"
            + "      \"first_seen\": \"2026-12-01T10:30:00Z\",\n"
            + "      \"name\": \"Servidor B\"\n"
            + "    }\n"
            + "  },\n"
            + "  \"addresses\": {\n"
            + "    \"otro.ejemplo.com\": \"" + ID_B.hex() + "\",\n"
            + "    \"play.ejemplo.com:25565\": \"" + ID_A.hex() + "\",\n"
            + "    \"wss://mc.ejemplo.com/a1b2c3\": \"" + ID_A.hex() + "\"\n"
            + "  }\n"
            + "}\n";
    }

    private static String servidor(ServerId id, String pin, String spki, String firstSeen, String name) {
        return "\"" + id.hex() + "\": {\"pin\": \"" + pin + "\", \"spki\": \"" + spki + "\", \"first_seen\": \""
            + firstSeen + "\", \"name\": \"" + name + "\"}";
    }
}
