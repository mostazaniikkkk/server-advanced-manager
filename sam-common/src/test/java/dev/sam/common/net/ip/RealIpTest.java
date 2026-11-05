package dev.sam.common.net.ip;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaders;

/**
 * IP real del jugador (RS-WS-02, TRANSPORTE_WEBSOCKET.md 4.4): las cabeceras de IP solo valen si
 * la IP del socket es un proxy de confianza; en cualquier otro caso se ignoran y se audita.
 */
public class RealIpTest {

    private static final String CF = "CF-Connecting-IP";
    private static final String XFF = "X-Forwarded-For";
    /** Dentro de 162.158.0.0/15, un rango publicado de Cloudflare. */
    private static final InetAddress BORDE_CF = ip("162.158.10.20");
    private static final InetAddress DIRECTO = ip("198.51.100.9");

    // ===== CIDR =====

    @Test
    void unCidrIpv4IncluyeSusBordesYNadaMas() {
        var red = Cidr.parse("10.0.0.0/8");
        assertThat(red.contains(ip("10.0.0.0"))).isTrue();
        assertThat(red.contains(ip("10.255.255.255"))).isTrue();
        assertThat(red.contains(ip("11.0.0.0"))).isFalse();
        assertThat(red.contains(ip("9.255.255.255"))).isFalse();
    }

    @Test
    void unPrefijoQueNoCaeEnUnByteSeRespetaBitABit() {
        var red = Cidr.parse("162.158.0.0/15");
        assertThat(red.contains(ip("162.159.255.255"))).isTrue();
        assertThat(red.contains(ip("162.160.0.0"))).isFalse();
        assertThat(red.contains(ip("162.157.255.255"))).isFalse();
        var otra = Cidr.parse("104.16.0.0/13");
        assertThat(otra.contains(ip("104.23.255.255"))).isTrue();
        assertThat(otra.contains(ip("104.24.0.0"))).isFalse();
    }

    @Test
    void losPrefijosExtremosIncluyenUnaSolaIpOTodaLaFamilia() {
        var una = Cidr.parse("203.0.113.7/32");
        assertThat(una.contains(ip("203.0.113.7"))).isTrue();
        assertThat(una.contains(ip("203.0.113.6"))).isFalse();
        var todas = Cidr.parse("0.0.0.0/0");
        assertThat(todas.contains(ip("255.255.255.255"))).isTrue();
        assertThat(todas.contains(ip("2001:db8::1"))).as("otra familia").isFalse();
    }

    @Test
    void unCidrIpv6NoIncluyeIpv4() {
        var red = Cidr.parse("2606:4700::/32");
        assertThat(red.contains(ip("2606:4700:abcd::1"))).isTrue();
        assertThat(red.contains(ip("2606:4701::"))).isFalse();
        assertThat(Cidr.parse("2a06:98c0::/29").contains(ip("2a06:98c7:ffff::1"))).isTrue();
        assertThat(Cidr.parse("2a06:98c0::/29").contains(ip("2a06:98c8::"))).isFalse();
        assertThat(Cidr.parse("::/0").contains(ip("10.0.0.1"))).isFalse();
    }

    @Test
    void unCidrInvalidoSeRechazaCitandoElValor() {
        for (var malo : List.of("10.0.0.0", "10.0.0.0/33", "::/129", "10.0.0.0/-1", "0.0.0.0/-1", "10.0.0.0/x", "10.0.0.0/",
                "example.com/8", "/8", "", "10.0.0.0/8/8", "1.2.3/24", "10.0.0.1/8", "2606:4700::1/32")) {
            assertThatThrownBy(() -> Cidr.parse(malo)).as(malo)
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("\"" + malo + "\"");
        }
    }

    // ===== Proxies de confianza =====

    @Test
    void cloudflareIncluyeTodosLosRangosPublicados() {
        var proxies = TrustedProxies.parse("cloudflare");
        assertThat(TrustedProxies.CLOUDFLARE_RANGES).hasSize(22)
            .contains("173.245.48.0/20", "131.0.72.0/22", "2400:cb00::/32", "2c0f:f248::/32");
        for (var rango : TrustedProxies.CLOUDFLARE_RANGES) {
            assertThat(proxies.contains(ip(rango.substring(0, rango.indexOf('/'))))).as(rango).isTrue();
        }
        assertThat(proxies.contains(ip("8.8.8.8"))).isFalse();
        assertThat(proxies.contains(DIRECTO)).isFalse();
    }

    @Test
    void unaListaDeCidrSeAceptaConEspaciosYJuntoACloudflare() {
        var propios = TrustedProxies.parse(" 10.0.0.0/8 , 192.168.1.0/24 ");
        assertThat(propios.contains(ip("10.1.2.3"))).isTrue();
        assertThat(propios.contains(ip("192.168.1.200"))).isTrue();
        assertThat(propios.contains(ip("192.168.2.1"))).isFalse();
        assertThat(propios.contains(BORDE_CF)).isFalse();
        var mixto = TrustedProxies.parse("CloudFlare,10.0.0.0/8");
        assertThat(mixto.contains(BORDE_CF)).isTrue();
        assertThat(mixto.contains(ip("10.1.2.3"))).isTrue();
    }

    @Test
    void vacioNoConfiaEnNadie() {
        for (var nada : List.of("", "  ", ",")) {
            assertThat(TrustedProxies.parse(nada).contains(BORDE_CF)).as("\"%s\"", nada).isFalse();
        }
        assertThat(TrustedProxies.none().contains(BORDE_CF)).isFalse();
    }

    @Test
    void unaEntradaInvalidaRechazaLaLista() {
        assertThatThrownBy(() -> TrustedProxies.parse("10.0.0.0/8,proxy.local"))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("proxy.local");
    }

    // ===== Cabecera configurada =====

    @Test
    void laCabeceraSeEligeSinDistinguirMayusculas() {
        assertThat(RealIpHeader.parse(" cf-connecting-ip ")).isEqualTo(RealIpHeader.CF_CONNECTING_IP);
        assertThat(RealIpHeader.parse("X-FORWARDED-FOR")).isEqualTo(RealIpHeader.X_FORWARDED_FOR);
        assertThatThrownBy(() -> RealIpHeader.parse("X-Real-IP"))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(CF).hasMessageContaining(XFF);
    }

    // ===== Resolución =====

    @Test
    void sinProxyLaIpEsLaDelSocketYNoSeAudita() {
        var audit = new Auditoria();
        assertThat(resolver("cloudflare", RealIpHeader.CF_CONNECTING_IP, audit).resolve(DIRECTO, cabeceras()))
            .isEqualTo(DIRECTO);
        assertThat(audit.eventos).isEmpty();
    }

    @Test
    void unaCabeceraDeIpDesdeUnOrigenNoConfiableSeIgnoraYSeAudita() {
        for (var cabecera : List.of(CF, XFF, "cf-connecting-ip")) {
            var audit = new Auditoria();
            var ip = resolver("cloudflare", RealIpHeader.CF_CONNECTING_IP, audit)
                .resolve(DIRECTO, cabeceras(cabecera, "203.0.113.7"));
            assertThat(ip).as(cabecera).isEqualTo(DIRECTO);
            assertThat(audit.eventos).as(cabecera).singleElement().asString()
                .contains("198.51.100.9").containsIgnoringCase(cabecera).doesNotContain("203.0.113.7");
        }
    }

    @Test
    void desdeUnProxyDeConfianzaSeTomaLaCabeceraConfigurada() {
        var audit = new Auditoria();
        var resolver = resolver("cloudflare", RealIpHeader.CF_CONNECTING_IP, audit);
        assertThat(resolver.resolve(BORDE_CF, cabeceras(CF, "203.0.113.7"))).isEqualTo(ip("203.0.113.7"));
        assertThat(resolver.resolve(BORDE_CF, cabeceras(CF, "2001:db8::7 "))).isEqualTo(ip("2001:db8::7"));
        assertThat(audit.eventos).isEmpty();
    }

    @Test
    void unProxyDeConfianzaSinCabeceraValidaDejaLaIpDelSocketYSeAudita() {
        var casos = new ArrayList<HttpHeaders>();
        casos.add(cabeceras());
        casos.add(cabeceras(XFF, "203.0.113.7"));
        casos.add(cabeceras(CF, "no-es-ip"));
        casos.add(cabeceras(CF, "jugador.example"));
        casos.add(cabeceras(CF, "203.0.113.7, 203.0.113.8"));
        casos.add(cabeceras(CF, ""));
        casos.add(cabeceras(CF, "203.0.113.7").add(CF, "203.0.113.8"));
        for (var caso : casos) {
            var audit = new Auditoria();
            assertThat(resolver("cloudflare", RealIpHeader.CF_CONNECTING_IP, audit).resolve(BORDE_CF, caso))
                .as(caso.toString()).isEqualTo(BORDE_CF);
            assertThat(audit.eventos).as(caso.toString()).singleElement().asString()
                .contains("162.158.10.20").contains(CF);
        }
    }

    @Test
    void xForwardedForUsaElUltimoSaltoAgregadoPorElProxy() {
        var audit = new Auditoria();
        var resolver = resolver("10.0.0.0/8", RealIpHeader.X_FORWARDED_FOR, audit);
        var proxy = ip("10.0.0.5");
        assertThat(resolver.resolve(proxy, cabeceras(XFF, "1.1.1.1, 203.0.113.7"))).isEqualTo(ip("203.0.113.7"));
        assertThat(resolver.resolve(proxy, cabeceras(XFF, "203.0.113.9"))).isEqualTo(ip("203.0.113.9"));
        assertThat(resolver.resolve(proxy, cabeceras(XFF, "1.1.1.1").add(XFF, "2.2.2.2,203.0.113.8 ")))
            .as("la última línea, su último elemento").isEqualTo(ip("203.0.113.8"));
        assertThat(audit.eventos).isEmpty();
        assertThat(resolver.resolve(proxy, cabeceras(XFF, "203.0.113.7,"))).isEqualTo(proxy);
        assertThat(resolver.resolve(proxy, cabeceras(CF, "203.0.113.7"))).as("otra cabecera").isEqualTo(proxy);
        assertThat(audit.eventos).hasSize(2).allMatch(e -> e.contains(XFF));
    }

    @Test
    void laIpResueltaQuedaEnLaConexion() {
        var canal = canalDesde(BORDE_CF);
        assertThat(ClientIp.of(canal)).as("antes de resolver, la del socket").contains(BORDE_CF);
        resolver("cloudflare", RealIpHeader.CF_CONNECTING_IP, IngressAudit.NONE).apply(canal, cabeceras(CF, "203.0.113.7"));
        assertThat(ClientIp.of(canal)).contains(ip("203.0.113.7"));
    }

    @Test
    void unaConexionSinDireccionIpNoTieneIpDeCliente() {
        var canal = new EmbeddedChannel();
        resolver("cloudflare", RealIpHeader.CF_CONNECTING_IP, IngressAudit.NONE).apply(canal, cabeceras(CF, "203.0.113.7"));
        assertThat(ClientIp.of(canal)).isEmpty();
        assertThat(ClientIp.of(canalDesde(null))).as("dirección sin resolver").isEmpty();
    }

    // ===== Ayudantes =====

    public static final class Auditoria implements IngressAudit {
        public final List<String> eventos = new ArrayList<>();

        @Override
        public void record(String message) {
            eventos.add(message);
        }
    }

    private static RealIpResolver resolver(String proxies, RealIpHeader header, IngressAudit audit) {
        return new RealIpResolver(TrustedProxies.parse(proxies), header, audit);
    }

    private static HttpHeaders cabeceras(String... pares) {
        var headers = new DefaultHttpHeaders();
        for (int i = 0; i < pares.length; i += 2) {
            headers.add(pares[i], pares[i + 1]);
        }
        return headers;
    }

    /** Un canal cuyo socket remoto es {@code ip} ({@code null}: dirección sin resolver). */
    public static EmbeddedChannel canalDesde(InetAddress ip) {
        SocketAddress remota = ip == null ? InetSocketAddress.createUnresolved("jugador.example", 25565)
            : new InetSocketAddress(ip, 40000);
        return new EmbeddedChannel() {
            @Override
            protected SocketAddress remoteAddress0() {
                return remota;
            }
        };
    }

    public static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
