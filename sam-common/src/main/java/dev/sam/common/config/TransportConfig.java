package dev.sam.common.config;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.gate.ConnectionGuard;
import dev.sam.common.net.ip.IngressAudit;
import dev.sam.common.net.ip.RealIpHeader;
import dev.sam.common.net.ip.RealIpResolver;
import dev.sam.common.net.ip.TrustedProxies;
import dev.sam.common.net.ws.WebSocketUpgrade;

/**
 * Transporte según la configuración (REQUERIMIENTOS.md 8.3, RF-WS-01/02/03). Por defecto solo TCP.
 * El WebSocket exige {@value #WS_PATH}; con él aplican {@value #TRUSTED_PROXIES} (por defecto
 * Cloudflare) y {@value #REAL_IP_HEADER} (RS-WS-02). Un valor inválido no se interpreta: se rechaza con
 * {@link IllegalArgumentException} nombrando la clave (RF-CFG-04).
 *
 * @param webSocketPath la ruta, solo si el WebSocket está activo
 */
public record TransportConfig(IngressPolicy policy, Optional<String> webSocketPath, TrustedProxies trustedProxies,
        RealIpHeader realIpHeader, int unclassifiedPerIp, int unclassifiedGlobal) {

    public static final String TCP_ENABLED = "SAM_TCP_ENABLED";
    public static final String WS_ENABLED = "SAM_WS_ENABLED";
    public static final String WS_PATH = "SAM_WS_PATH";
    public static final String TRUSTED_PROXIES = "SAM_WS_TRUSTED_PROXIES";
    public static final String REAL_IP_HEADER = "SAM_WS_REAL_IP_HEADER";
    public static final String UNCLASSIFIED_PER_IP = "SAM_NET_UNCLASSIFIED_PER_IP";
    public static final String UNCLASSIFIED_GLOBAL = "SAM_NET_UNCLASSIFIED_GLOBAL";

    public static TransportConfig from(Map<String, String> values) {
        var tcp = bool(values, TCP_ENABLED, true);
        var ws = bool(values, WS_ENABLED, false);
        var perIp = positive(values, UNCLASSIFIED_PER_IP, ConnectionGuard.DEFAULT_PER_IP);
        var globalLimit = positive(values, UNCLASSIFIED_GLOBAL, ConnectionGuard.DEFAULT_GLOBAL);
        // Ambos en false: lo rechaza IngressPolicy, nombrando las dos claves
        if (!ws) {
            return new TransportConfig(new IngressPolicy(tcp, false), Optional.empty(), TrustedProxies.none(), RealIpHeader.CF_CONNECTING_IP,
                perIp, globalLimit);
        }
        var path = values.getOrDefault(WS_PATH, "").trim();
        try {
            WebSocketUpgrade.validatePath(path);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(WS_ENABLED + "=true exige un " + WS_PATH + " válido: " + e.getMessage(), e);
        }
        return new TransportConfig(new IngressPolicy(tcp, true), Optional.of(path),
            parsed(values, TRUSTED_PROXIES, TrustedProxies.CLOUDFLARE, TrustedProxies::parse),
            parsed(values, REAL_IP_HEADER, RealIpHeader.CF_CONNECTING_IP.headerName(), RealIpHeader::parse), perIp, globalLimit);
    }

    /** Límites de conexiones sin clasificar (PROTOCOLO.md 10, RS-WS-03). */
    public ConnectionGuard guard() {
        return new ConnectionGuard(unclassifiedPerIp, unclassifiedGlobal, trustedProxies::contains);
    }

    /** La IP del cliente según estos proxies y cabecera (RS-WS-02). */
    public RealIpResolver realIp(IngressAudit audit) {
        return new RealIpResolver(trustedProxies, realIpHeader, audit);
    }

    private static <T> T parsed(Map<String, String> values, String key, String byDefault, Function<String, T> parser) {
        try {
            return parser.apply(values.getOrDefault(key, byDefault));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(key + ": " + e.getMessage(), e);
        }
    }

    private static int positive(Map<String, String> values, String key, int byDefault) {
        var raw = values.get(key);
        if (raw == null) {
            return byDefault;
        }
        int value;
        try {
            value = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            value = 0;
        }
        if (value < 1) {
            throw new IllegalArgumentException(key + " debe ser un entero positivo, no \"" + raw + "\"");
        }
        return value;
    }

    private static boolean bool(Map<String, String> values, String key, boolean byDefault) {
        var raw = values.get(key);
        if (raw == null) {
            return byDefault;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new IllegalArgumentException(key + " debe ser true o false, no \"" + raw + "\"");
        };
    }
}
