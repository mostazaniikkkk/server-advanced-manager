package dev.sam.common.net.ip;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * {@code SAM_WS_TRUSTED_PROXIES} (RS-WS-02): proxies cuyas cabeceras de IP se aceptan. Lista de
 * CIDR separados por comas; {@value #CLOUDFLARE} agrega los rangos publicados de Cloudflare.
 * Vacío: no se confía en nadie y la IP es siempre la del socket.
 */
public final class TrustedProxies {

    public static final String CLOUDFLARE = "cloudflare";

    /**
     * https://www.cloudflare.com/ips-v4 y /ips-v6, consultados el 2026-11-05. Se revisan con cada
     * release; el operador puede reemplazarlos con su propia lista.
     */
    static final List<String> CLOUDFLARE_RANGES = List.of(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32");

    private final List<Cidr> ranges;

    private TrustedProxies(List<Cidr> ranges) {
        this.ranges = ranges;
    }

    public static TrustedProxies none() {
        return new TrustedProxies(List.of());
    }

    /** @throws IllegalArgumentException si alguna entrada no es un CIDR ni {@value #CLOUDFLARE} */
    public static TrustedProxies parse(String text) {
        var ranges = new ArrayList<Cidr>();
        for (var entry : text.split(",")) {
            var value = entry.trim();
            if (value.toLowerCase(Locale.ROOT).equals(CLOUDFLARE)) {
                CLOUDFLARE_RANGES.forEach(range -> ranges.add(Cidr.parse(range)));
            } else if (!value.isEmpty()) {
                ranges.add(Cidr.parse(value));
            }
        }
        return new TrustedProxies(List.copyOf(ranges));
    }

    public boolean contains(InetAddress address) {
        return ranges.stream().anyMatch(range -> range.contains(address));
    }
}
