package dev.sam.common.config;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.ws.WebSocketUpgrade;

/**
 * Transporte según la configuración (REQUERIMIENTOS.md 8.3, RF-WS-01/02/03). Por defecto solo TCP.
 * El WebSocket exige {@value #WS_PATH}. Un valor inválido no se interpreta: se rechaza con
 * {@link IllegalArgumentException} nombrando la clave (RF-CFG-04).
 *
 * @param webSocketPath la ruta, solo si el WebSocket está activo
 */
public record TransportConfig(IngressPolicy policy, Optional<String> webSocketPath) {

    public static final String TCP_ENABLED = "SAM_TCP_ENABLED";
    public static final String WS_ENABLED = "SAM_WS_ENABLED";
    public static final String WS_PATH = "SAM_WS_PATH";

    public static TransportConfig from(Map<String, String> values) {
        var tcp = bool(values, TCP_ENABLED, true);
        var ws = bool(values, WS_ENABLED, false);
        // Ambos en false: lo rechaza IngressPolicy, nombrando las dos claves
        if (!ws) {
            return new TransportConfig(new IngressPolicy(tcp, false), Optional.empty());
        }
        var path = values.getOrDefault(WS_PATH, "").trim();
        try {
            WebSocketUpgrade.validatePath(path);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(WS_ENABLED + "=true exige un " + WS_PATH + " válido: " + e.getMessage(), e);
        }
        return new TransportConfig(new IngressPolicy(tcp, true), Optional.of(path));
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
