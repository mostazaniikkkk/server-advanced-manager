package dev.sam.common.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * RF-ADM-05a (H-04 de HARDENING.md): la caducidad de las sesiones de juego. La sesión verificada con 2FA de un
 * admin dura {@code adminTtl} desde el login; cualquier sesión, {@code sessionTtl}. Seguro entre hilos.
 */
public final class SessionClock {

    public static final String ADMIN_TTL = "SAM_POLICY_ADMIN_SESSION_TTL";
    public static final String SESSION_TTL = "SAM_POLICY_DEFAULT_SESSION_TTL";
    private static final Pattern DURATION = Pattern.compile("([1-9]\\d{0,5})([smhd])");

    private static final class Session {
        final String nick;
        final Instant start;
        final boolean verified;
        boolean notified;

        Session(String nick, Instant start, boolean verified) {
            this.nick = nick;
            this.start = start;
            this.verified = verified;
        }
    }

    private final Duration adminTtl;
    private final Duration sessionTtl;
    private final Map<String, Session> sessions = new LinkedHashMap<>();

    public SessionClock(Duration adminTtl, Duration sessionTtl) {
        this.adminTtl = adminTtl;
        this.sessionTtl = sessionTtl;
    }

    public static SessionClock fromConfig(Map<String, String> config) {
        return new SessionClock(parse(ADMIN_TTL, config.getOrDefault(ADMIN_TTL, "12h")),
            parse(SESSION_TTL, config.getOrDefault(SESSION_TTL, "7d")));
    }

    /** Un número positivo y {@code s}, {@code m}, {@code h} o {@code d}. */
    public static Duration parse(String name, String value) {
        var matcher = DURATION.matcher(value.strip());
        if (!matcher.matches()) {
            throw new IllegalArgumentException(name + " debe ser un número positivo y s, m, h o d (por ejemplo 12h)");
        }
        var amount = Long.parseLong(matcher.group(1));
        return switch (matcher.group(2)) {
            case "s" -> Duration.ofSeconds(amount);
            case "m" -> Duration.ofMinutes(amount);
            case "h" -> Duration.ofHours(amount);
            default -> Duration.ofDays(amount);
        };
    }

    /** Empieza (o reinicia) la sesión al entrar; {@code verified}: completó el 2FA. */
    public synchronized void start(String nick, boolean verified, Instant now) {
        sessions.put(key(nick), new Session(nick, now, verified));
    }

    /** Si la sesión verificada sigue vigente (RF-ADM-04 + 05a). */
    public synchronized boolean verified(String nick, Instant now) {
        var session = sessions.get(key(nick));
        return session != null && session.verified && now.isBefore(session.start.plus(adminTtl));
    }

    /** Los admins cuya sesión verificada acaba de vencer (cada uno una sola vez), para avisarles. */
    public synchronized List<String> adminExpired(Instant now) {
        var out = new ArrayList<String>();
        for (var session : sessions.values()) {
            if (session.verified && !session.notified && !now.isBefore(session.start.plus(adminTtl))) {
                session.notified = true;
                out.add(session.nick);
            }
        }
        return out;
    }

    /** Las sesiones que llegaron a su máximo: se quitan y se devuelven para desconectarlas. */
    public synchronized List<String> expired(Instant now) {
        var out = new ArrayList<String>();
        var it = sessions.values().iterator();
        while (it.hasNext()) {
            var session = it.next();
            if (!now.isBefore(session.start.plus(sessionTtl))) {
                out.add(session.nick);
                it.remove();
            }
        }
        return out;
    }

    public synchronized void forget(String nick) {
        sessions.remove(key(nick));
    }

    private static String key(String nick) {
        return nick.toLowerCase(Locale.ROOT);
    }
}
