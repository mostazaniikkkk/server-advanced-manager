package dev.sam.common.net.ip;

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;

/** {@code SAM_WS_REAL_IP_HEADER}: de qué cabecera sale la IP real cuando el proxy es de confianza. */
public enum RealIpHeader {
    /** Cloudflare: una sola cabecera con una sola IP. */
    CF_CONNECTING_IP("CF-Connecting-IP"),
    /** nginx, Caddy: lista separada por comas; vale el último salto, el que agregó el proxy. */
    X_FORWARDED_FOR("X-Forwarded-For");

    private final String headerName;

    RealIpHeader(String headerName) {
        this.headerName = headerName;
    }

    public String headerName() {
        return headerName;
    }

    /** Sin distinguir mayúsculas. @throws IllegalArgumentException si no es una de las conocidas */
    public static RealIpHeader parse(String text) {
        for (var header : values()) {
            if (header.headerName.equalsIgnoreCase(text.trim())) {
                return header;
            }
        }
        throw new IllegalArgumentException("debe ser " + CF_CONNECTING_IP.headerName + " o " + X_FORWARDED_FOR.headerName);
    }

    /** La IP de los valores recibidos de esta cabecera, si es exactamente una IP válida. */
    Optional<InetAddress> extract(List<String> values) {
        if (this == CF_CONNECTING_IP) {
            return values.size() == 1 ? IpLiteral.parse(values.get(0).trim()) : Optional.empty();
        }
        if (values.isEmpty()) {
            return Optional.empty();
        }
        var hops = values.get(values.size() - 1).split(",", -1);
        return IpLiteral.parse(hops[hops.length - 1].trim());
    }
}
