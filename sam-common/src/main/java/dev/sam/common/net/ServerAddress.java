package dev.sam.common.net;

import java.net.IDN;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Dirección de servidor normalizada: la clave del almacén de pins (PROTOCOLO.md 3.3).
 *
 * <p>Formas aceptadas: {@code host}, {@code host:puerto}, {@code [ipv6]}, {@code [ipv6]:puerto},
 * {@code ws://host[:puerto][/ruta]} y {@code wss://host[:puerto][/ruta]}.
 *
 * <p>Reglas:
 * <ul>
 *   <li>Host en minúsculas, sin punto final; nombres no ASCII en punycode (como vanilla).</li>
 *   <li>IPv4 sin ceros a la izquierda; IPv6 en su forma completa entre corchetes. <b>Nunca se
 *       consulta el DNS.</b></li>
 *   <li>En TCP, una dirección sin puerto usa la búsqueda SRV de Minecraft y puede llevar a otro
 *       destino que la misma con {@code :25565}: <b>no son equivalentes</b>.</li>
 *   <li>En WebSocket no hay SRV: el puerto por defecto (80 / 443) se omite. La ruta distingue
 *       mayúsculas; vacía equivale a {@code /}.</li>
 * </ul>
 */
public final class ServerAddress {

    public enum Transport {
        TCP("", 25565), WS("ws://", 80), WSS("wss://", 443);

        private final String prefix;
        private final int defaultPort;

        Transport(String prefix, int defaultPort) {
            this.prefix = prefix;
            this.defaultPort = defaultPort;
        }
    }

    public static final int MAX_HOST_LENGTH = 253;
    public static final int MAX_PATH_LENGTH = 256;

    /** {@code ws[s]://autoridad[/ruta]}; el esquema no distingue mayúsculas. */
    private static final Pattern WEBSOCKET = Pattern.compile("(?i)(wss?)://([^/]*)(/.*)?");
    /** {@code [ipv6][:puerto]} o {@code host[:puerto]}; un ':' de más deja la entrada sin coincidencia. */
    private static final Pattern AUTHORITY = Pattern.compile("(?:\\[([^\\]]*)\\]|([^:\\[\\]]*))(?::([^:]*))?");
    /** Hasta 5 cifras significativas; se admiten ceros a la izquierda (025565). */
    private static final Pattern PORT = Pattern.compile("0*([1-9][0-9]{0,4})");
    private static final Pattern NUMERIC_HOST = Pattern.compile("[0-9.]+");
    private static final Pattern IPV4_OCTET = Pattern.compile("0|[1-9][0-9]{0,2}");
    /** Sin '%': un zone ID ("fe80::1%1") es local a cada máquina y no sirve en un pin. */
    private static final Pattern IPV6_CHARS = Pattern.compile("[0-9a-fA-F:.]+");
    private static final Pattern PATH = Pattern.compile("/[A-Za-z0-9\\-._~!$&'()*+,;=:@%/]*");

    private final Transport transport;
    private final String host;
    private final int port;
    private final boolean explicitPort;
    private final String path;
    private final String canonical;

    private ServerAddress(Transport transport, String host, int port, boolean explicitPort, String path) {
        this.transport = transport;
        this.host = host;
        this.port = port;
        this.explicitPort = explicitPort;
        this.path = path;
        var portSuffix = keepsPort() ? ":" + port : "";
        this.canonical = transport.prefix + host + portSuffix + path;
    }

    public static ServerAddress parse(String input) {
        var text = input.strip();
        var transport = Transport.TCP;
        var authority = text;
        var path = "";
        var webSocket = WEBSOCKET.matcher(text);
        if (webSocket.matches()) {
            transport = webSocket.group(1).equalsIgnoreCase("wss") ? Transport.WSS : Transport.WS;
            authority = webSocket.group(2);
            path = webSocket.group(3) == null ? "/" : webSocket.group(3);
            if (path.length() > MAX_PATH_LENGTH || !PATH.matcher(path).matches()) {
                throw invalid(input, "ruta inválida");
            }
        } else if (text.contains("://")) {
            throw invalid(input, "esquema no soportado");
        }

        var parts = AUTHORITY.matcher(authority);
        if (!parts.matches()) {
            throw invalid(input, "se esperaba host[:puerto] o [ipv6][:puerto]");
        }
        var host = parts.group(1) != null ? normalizeIpv6(input, parts.group(1)) : normalizeName(input, parts.group(2));
        var rawPort = parts.group(3);
        int port = rawPort == null ? transport.defaultPort : parsePort(input, rawPort);
        return new ServerAddress(transport, host, port, rawPort != null, path);
    }

    private static int parsePort(String input, String rawPort) {
        var digits = PORT.matcher(rawPort);
        if (!digits.matches() || Integer.parseInt(digits.group(1)) > 65535) {
            throw invalid(input, "puerto inválido (1-65535)");
        }
        return Integer.parseInt(digits.group(1));
    }

    private static String normalizeName(String input, String rawHost) {
        var host = rawHost.endsWith(".") ? rawHost.substring(0, rawHost.length() - 1) : rawHost;
        if (host.isEmpty()) {
            throw invalid(input, "falta el host");
        }
        if (NUMERIC_HOST.matcher(host).matches()) {
            return normalizeIpv4(input, host);
        }
        String ascii;
        try {
            // STD3 rechaza etiquetas vacías, de más de 63 caracteres, con '_', espacios o guiones en los bordes
            ascii = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw invalid(input, "nombre de host inválido");
        }
        if (ascii.length() > MAX_HOST_LENGTH) {
            throw invalid(input, "nombre de host demasiado largo");
        }
        return ascii;
    }

    private static String normalizeIpv4(String input, String host) {
        var octets = host.split("\\.", -1);
        if (octets.length != 4) {
            throw invalid(input, "IPv4 inválido");
        }
        for (var octet : octets) {
            if (!IPV4_OCTET.matcher(octet).matches() || Integer.parseInt(octet) > 255) {
                throw invalid(input, "IPv4 inválido");
            }
        }
        return host;
    }

    private static String normalizeIpv6(String input, String literal) {
        if (!IPV6_CHARS.matcher(literal).matches()) {
            throw invalid(input, "IPv6 inválido");
        }
        try {
            // Entre corchetes, la JDK exige un literal IPv6 y nunca consulta el DNS
            var address = InetAddress.getByName("[" + literal + "]");
            return address instanceof Inet6Address
                ? "[" + address.getHostAddress() + "]"
                : address.getHostAddress();
        } catch (UnknownHostException e) {
            throw invalid(input, "IPv6 inválido");
        }
    }

    private static IllegalArgumentException invalid(String input, String reason) {
        return new IllegalArgumentException("Dirección de servidor inválida (" + reason + "): \"" + input + "\"");
    }

    private boolean keepsPort() {
        return transport == Transport.TCP ? explicitPort : port != transport.defaultPort;
    }

    public Transport transport() {
        return transport;
    }

    /** Host normalizado; un IPv6 va entre corchetes. */
    public String host() {
        return host;
    }

    /** Puerto efectivo (el explícito o el por defecto del transporte). */
    public int port() {
        return port;
    }

    /** Ruta del WebSocket (empieza con {@code /}); vacía en TCP. */
    public String path() {
        return path;
    }

    /** En TCP sin puerto explícito, el cliente vanilla consulta primero el registro SRV. */
    public boolean usesSrvLookup() {
        return transport == Transport.TCP && !explicitPort;
    }

    public String canonical() {
        return canonical;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ServerAddress that && canonical.equals(that.canonical);
    }

    @Override
    public int hashCode() {
        return canonical.hashCode();
    }

    @Override
    public String toString() {
        return canonical;
    }
}
