package dev.sam.common.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import dev.sam.common.net.ServerAddress.Transport;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Normalización de direcciones de servidor (claves del almacén de pins, PROTOCOLO.md 3.3).
 *
 * <p>Regla clave: en TCP, una dirección sin puerto usa la búsqueda SRV de Minecraft y puede
 * llevar a otro destino que la misma dirección con :25565, así que NO son equivalentes.
 */
class ServerAddressTest {

    @ParameterizedTest(name = "\"{0}\" → \"{1}\"")
    @CsvSource(delimiter = '|', value = {
        // TCP
        "play.ejemplo.com             | play.ejemplo.com",
        "Play.Ejemplo.COM             | play.ejemplo.com",
        "'  play.ejemplo.com  '       | play.ejemplo.com",
        "play.ejemplo.com.            | play.ejemplo.com",
        "play.ejemplo.com:25565       | play.ejemplo.com:25565",
        "play.ejemplo.com:025565      | play.ejemplo.com:25565",
        "PLAY.ejemplo.com:25570       | play.ejemplo.com:25570",
        "1.2.3.4                      | 1.2.3.4",
        "1.2.3.4:25570                | 1.2.3.4:25570",
        "255.255.255.255              | 255.255.255.255",
        "0.0.0.0                      | 0.0.0.0",
        "h.com:1                      | h.com:1",
        "h.com:65535                  | h.com:65535",
        "1.2.3.4.                     | 1.2.3.4",
        "[::1]                        | [0:0:0:0:0:0:0:1]",
        "[::1]:25565                  | [0:0:0:0:0:0:0:1]:25565",
        "[2001:DB8::1]                | [2001:db8:0:0:0:0:0:1]",
        "[::ffff:1.2.3.4]:25565       | 1.2.3.4:25565",
        "bücher.example               | xn--bcher-kva.example",
        "localhost                    | localhost",
        // WebSocket
        "wss://MC.Ejemplo.com/A1b2    | wss://mc.ejemplo.com/A1b2",
        "WSS://mc.ejemplo.com:443/x   | wss://mc.ejemplo.com/x",
        "wss://mc.ejemplo.com         | wss://mc.ejemplo.com/",
        "wss://mc.ejemplo.com:8443/x  | wss://mc.ejemplo.com:8443/x",
        "ws://mc.ejemplo.com:80/x     | ws://mc.ejemplo.com/x",
        "ws://mc.ejemplo.com:8080/x/  | ws://mc.ejemplo.com:8080/x/",
        "wss://[::1]:8443/p           | wss://[0:0:0:0:0:0:0:1]:8443/p",
        "wss://bücher.example/r       | wss://xn--bcher-kva.example/r",
    })
    void normaliza(String entrada, String canonica) {
        assertThat(ServerAddress.parse(entrada).canonical()).isEqualTo(canonica);
    }

    @ParameterizedTest(name = "rechaza \"{0}\"")
    @ValueSource(strings = {
        "", "   ",
        // puertos
        "h.com:0", "h.com:65536", "h.com:abc", "h.com:", "h.com:-1", ":25565", "h.com:1:2",
        // formas no permitidas
        "user@h.com", "user@h.com:25565", "http://h.com", "sam://h.com", "tcp://h.com", "h.com/x",
        // hosts inválidos
        "ex ample.com", "a_b.com", "-malo.com", "malo-.com", "a..b.com", ".com",
        "01.2.3.4", "256.1.1.1", "1.2.3", "1.2.3.4.5",
        // IPv6
        "::1", "[::1", "::1]", "[zz::1]", "[fe80::1%eth0]", "[1:2]", "[::1]x", "[::1]:", "[]", "[example.com]",
        // zone ID numérico: la JDK lo acepta, pero es local a cada máquina
        "[fe80::1%1]", "[fe80::1%25]",
        // host vacío o solo un punto
        ".", "wss://./x",
        // WebSocket
        "wss://h.com/x?y=1", "wss://h.com/x#f", "wss://h.com/a b", "wss://", "wss:///x", "wss://user@h.com/x",
        "wss://h.com:0/x", "wss://h.com/ñ",
    })
    void rechazaDireccionesInvalidas(String entrada) {
        assertThatThrownBy(() -> ServerAddress.parse(entrada)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest(name = "\"{0}\" explica: {1}")
    @CsvSource(delimiter = '|', value = {
        "http://h.com          | esquema no soportado",
        "sam://h.com           | esquema no soportado",
        "h.com:70000           | puerto inválido",
        "wss://h.com/a?b       | ruta inválida",
        "[zz::1]               | IPv6 inválido",
        "256.0.0.1             | IPv4 inválido",
        "a_b.com               | nombre de host inválido",
        "h.com:1:2             | se esperaba host[:puerto]",
        "wss:///x              | falta el host",
    })
    void elMensajeDeErrorExplicaElProblemaYMuestraLaEntrada(String entrada, String motivo) {
        assertThatThrownBy(() -> ServerAddress.parse(entrada))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining(motivo)
            .hasMessageContaining(entrada);
    }

    @Test
    void rechazaEtiquetasDeMasDe63CaracteresYHostsDeMasDe253() {
        var etiqueta63 = "a".repeat(63);
        assertThat(ServerAddress.parse(etiqueta63 + ".com").host()).hasSize(67);
        assertThatThrownBy(() -> ServerAddress.parse("a".repeat(64) + ".com")).isInstanceOf(IllegalArgumentException.class);

        var host253 = String.join(".", etiqueta63, etiqueta63, etiqueta63, "a".repeat(61));
        assertThat(host253).hasSize(253);
        assertThat(ServerAddress.parse(host253).host()).isEqualTo(host253);
        assertThatThrownBy(() -> ServerAddress.parse(host253 + "a")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rechazaRutasDeMasDe256Caracteres() {
        assertThat(ServerAddress.parse("wss://h.com/" + "a".repeat(255)).path()).hasSize(256);
        assertThatThrownBy(() -> ServerAddress.parse("wss://h.com/" + "a".repeat(256)))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // ===== Semántica =====

    @Test
    void sinPuertoUsaSrvYNoEsEquivalenteAlPuertoExplicito() {
        var sinPuerto = ServerAddress.parse("play.ejemplo.com");
        var conPuerto = ServerAddress.parse("play.ejemplo.com:25565");
        assertThat(sinPuerto.usesSrvLookup()).isTrue();
        assertThat(conPuerto.usesSrvLookup()).isFalse();
        assertThat(sinPuerto).isNotEqualTo(conPuerto);
        assertThat(sinPuerto.port()).isEqualTo(25565);
        assertThat(conPuerto.port()).isEqualTo(25565);
    }

    @Test
    void enWebSocketElPuertoPorDefectoEsEquivalenteAlExplicito() {
        assertThat(ServerAddress.parse("wss://h.com/x")).isEqualTo(ServerAddress.parse("wss://h.com:443/x"))
            .hasSameHashCodeAs(ServerAddress.parse("wss://h.com:443/x"));
        assertThat(ServerAddress.parse("ws://h.com/x").port()).isEqualTo(80);
        assertThat(ServerAddress.parse("wss://h.com/x").port()).isEqualTo(443);
        assertThat(ServerAddress.parse("wss://h.com/x").usesSrvLookup()).isFalse();
    }

    @Test
    void laRutaDistingueMayusculasYLaBarraFinal() {
        assertThat(ServerAddress.parse("wss://h.com/Ab")).isNotEqualTo(ServerAddress.parse("wss://h.com/ab"));
        assertThat(ServerAddress.parse("wss://h.com/ab")).isNotEqualTo(ServerAddress.parse("wss://h.com/ab/"));
    }

    @Test
    void exponeSusPartes() {
        var tcp = ServerAddress.parse("Play.Ejemplo.com:25570");
        assertThat(tcp.transport()).isEqualTo(Transport.TCP);
        assertThat(tcp.host()).isEqualTo("play.ejemplo.com");
        assertThat(tcp.port()).isEqualTo(25570);
        assertThat(tcp.path()).isEmpty();

        var ws = ServerAddress.parse("wss://[::1]/sam");
        assertThat(ws.transport()).isEqualTo(Transport.WSS);
        assertThat(ws.host()).isEqualTo("[0:0:0:0:0:0:0:1]");
        assertThat(ws.path()).isEqualTo("/sam");
        assertThat(ServerAddress.parse("ws://h.com").transport()).isEqualTo(Transport.WS);
    }

    @Test
    void direccionesDistintasTienenHashesDistintos() {
        var hashes = java.util.stream.Stream.of("a.com", "b.com", "a.com:1", "wss://a.com/", "ws://a.com/", "wss://a.com/x")
            .map(d -> ServerAddress.parse(d).hashCode())
            .distinct()
            .count();
        assertThat(hashes).isEqualTo(6);
    }

    @Test
    void toStringEsLaFormaCanonica() {
        assertThat(ServerAddress.parse("WSS://H.com/x")).hasToString("wss://h.com/x");
        assertThat((Object) ServerAddress.parse("h.com")).isNotEqualTo("h.com");
    }

    @Test
    void validarUnIpv6NoConsultaElDns() {
        // Un literal inválido con caracteres "posibles" no debe tratarse como nombre a resolver
        assertThatThrownBy(() -> ServerAddress.parse("[1:2:3]")).isInstanceOf(IllegalArgumentException.class);
    }

    // ===== Propiedades =====

    @Property
    void normalizarEsIdempotente(@ForAll("direcciones") String entrada) {
        var una = ServerAddress.parse(entrada);
        var dos = ServerAddress.parse(una.canonical());
        assertThat(dos).isEqualTo(una);
        assertThat(dos.canonical()).isEqualTo(una.canonical());
    }

    @Property
    void mayusculasEnElHostNoCambianLaDireccion(@ForAll("direcciones") String entrada) {
        var hostEnMayusculas = entrada.contains("://")
            ? entrada.substring(0, entrada.indexOf("://") + 3) + upperHost(entrada.substring(entrada.indexOf("://") + 3))
            : upperHost(entrada);
        assertThat(ServerAddress.parse(hostEnMayusculas)).isEqualTo(ServerAddress.parse(entrada));
    }

    @Provide
    Arbitrary<String> direcciones() {
        var etiqueta = Arbitraries.strings().withChars("abcdefghijklmnopqrstuvwxyz0123456789").ofMinLength(1).ofMaxLength(12);
        var host = etiqueta.list().ofMinSize(1).ofMaxSize(4).map(l -> String.join(".", l) + ".net");
        var puerto = Arbitraries.integers().between(1, 65535);
        var ruta = Arbitraries.strings().withChars("abcdefghijABCDEFGHIJ0123456789-_/").ofMaxLength(20).map(r -> "/" + r);
        var tcp = Combinators.combine(host, puerto, Arbitraries.of(true, false))
            .as((h, p, conPuerto) -> conPuerto ? h + ":" + p : h);
        var ws = Combinators.combine(Arbitraries.of("ws", "wss", "WSS"), host, puerto, ruta)
            .as((s, h, p, r) -> s + "://" + h + ":" + p + r);
        return Arbitraries.oneOf(tcp, ws);
    }

    private static String upperHost(String resto) {
        int fin = resto.indexOf('/');
        int dosPuntos = resto.indexOf(':');
        int corte = fin < 0 ? resto.length() : fin;
        if (dosPuntos >= 0 && dosPuntos < corte) {
            corte = dosPuntos;
        }
        return resto.substring(0, corte).toUpperCase(java.util.Locale.ROOT) + resto.substring(corte);
    }
}
