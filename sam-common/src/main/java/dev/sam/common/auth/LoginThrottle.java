package dev.sam.common.auth;

import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * RF-AUTH-06 / RF-AUTH-06a (H-03 de HARDENING.md): bloqueo exponencial por (cuenta, IP), uno global de la
 * cuenta más suave (4 veces los fallos, desde cualquier IP) y el tope de logins pendientes por IP y global.
 * Todo en memoria: sobrevive a la reconexión, no a un reinicio. Seguro entre hilos.
 */
public final class LoginThrottle {

    /** Con más contadores que esto, cada fallo descarta los que llevan 24 h sin fallos ni bloqueo. */
    static final int PRUNE_ABOVE = 10_000;
    private static final int ACCOUNT_FACTOR = 4;
    private static final Duration MAX_LOCK = Duration.ofHours(24);
    private static final Duration FORGET_AFTER = Duration.ofHours(24);

    /**
     * @param maxAttempts fallos del par (cuenta, IP) que lo bloquean ({@code SAM_AUTH_MAX_ATTEMPTS})
     * @param base el primer bloqueo; cada repetición lo dobla ({@code SAM_AUTH_LOCKOUT_BASE})
     * @param pendingPerIp logins pendientes por IP ({@code SAM_AUTH_PENDING_PER_IP})
     * @param pendingGlobal logins pendientes en total ({@code SAM_AUTH_PENDING_GLOBAL})
     */
    public record Limits(int maxAttempts, Duration base, int pendingPerIp, int pendingGlobal) {
        public Limits {
            if (maxAttempts < 1 || base.isZero() || base.isNegative() || pendingPerIp < 1 || pendingGlobal < 1) {
                throw new IllegalArgumentException("límites de login inválidos");
            }
        }

        /** Del .env, con los valores por defecto de REQUERIMIENTOS 8.3; un valor inválido es un error de configuración. */
        public static Limits fromConfig(java.util.Map<String, String> config) {
            return new Limits(integer(config, "SAM_AUTH_MAX_ATTEMPTS", "5"), duration(config, "SAM_AUTH_LOCKOUT_BASE", "15m"),
                integer(config, "SAM_AUTH_PENDING_PER_IP", "3"), integer(config, "SAM_AUTH_PENDING_GLOBAL", "50"));
        }

        private static int integer(java.util.Map<String, String> config, String name, String fallback) {
            try {
                return Integer.parseInt(config.getOrDefault(name, fallback).strip());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(name + " no es un número");
            }
        }

        private static Duration duration(java.util.Map<String, String> config, String name, String fallback) {
            var value = config.getOrDefault(name, fallback).strip();
            var matcher = java.util.regex.Pattern.compile("(\\d{1,6})([smh])").matcher(value);
            if (!matcher.matches()) {
                throw new IllegalArgumentException(name + " debe ser un número y s, m o h (por ejemplo 15m)");
            }
            var amount = Long.parseLong(matcher.group(1));
            return switch (matcher.group(2)) {
                case "s" -> Duration.ofSeconds(amount);
                case "m" -> Duration.ofMinutes(amount);
                default -> Duration.ofHours(amount);
            };
        }
    }

    /** Fallos, el último bloqueo (para doblarlo), hasta cuándo y el último fallo. */
    private static final class Counter {
        int failures;
        Duration lastLock;
        Instant lockedUntil = Instant.MIN;
        Instant lastFailure = Instant.MIN;
    }

    private final Limits limits;
    private final InstantSource clock;
    private final Map<String, Counter> pairs = new HashMap<>();
    private final Map<String, Counter> accounts = new HashMap<>();
    private final Map<String, Integer> pending = new HashMap<>();
    private int pendingTotal;

    public LoginThrottle(Limits limits, InstantSource clock) {
        this.limits = limits;
        this.clock = clock;
    }

    /** Hasta cuándo no puede intentar: el más largo entre el bloqueo del par y el de la cuenta. */
    public synchronized Optional<Instant> lockedUntil(String account, String ip) {
        var now = clock.instant();
        return latest(locked(pairs.get(pair(account, ip)), now), locked(accounts.get(key(account)), now));
    }

    /** Cuenta un fallo; si con él se bloquea, devuelve hasta cuándo. */
    public synchronized Optional<Instant> failure(String account, String ip) {
        var now = clock.instant();
        if (pairs.size() + accounts.size() > PRUNE_ABOVE) {
            prune(now);
        }
        var byPair = fail(pairs.computeIfAbsent(pair(account, ip), k -> new Counter()), limits.maxAttempts(), now);
        var byAccount = fail(accounts.computeIfAbsent(key(account), k -> new Counter()),
            limits.maxAttempts() * ACCOUNT_FACTOR, now);
        return latest(byPair, byAccount);
    }

    /** Login correcto: se olvidan los fallos y niveles del par y de la cuenta. */
    public synchronized void success(String account, String ip) {
        pairs.remove(pair(account, ip));
        accounts.remove(key(account));
    }

    /** Un login pendiente más desde esta IP, si cabe. */
    public synchronized boolean enter(String ip) {
        var mine = pending.getOrDefault(ip, 0);
        if (mine >= limits.pendingPerIp() || pendingTotal >= limits.pendingGlobal()) {
            return false;
        }
        pending.put(ip, mine + 1);
        pendingTotal++;
        return true;
    }

    /** Terminó (bien, mal o por desconexión) un login pendiente de esta IP. */
    public synchronized void leave(String ip) {
        var mine = pending.get(ip);
        if (mine == null) {
            return;
        }
        if (mine == 1) {
            pending.remove(ip);
        } else {
            pending.put(ip, mine - 1);
        }
        pendingTotal--;
    }

    /** Cuánto falta para {@code until} según el reloj del limitador. */
    public Duration remaining(Instant until) {
        return Duration.between(clock.instant(), until);
    }

    synchronized int size() {
        return pairs.size() + accounts.size();
    }

    private Optional<Instant> fail(Counter counter, int threshold, Instant now) {
        if (stale(counter, now)) {
            counter.lastLock = null;
            counter.failures = 0;
        }
        counter.lastFailure = now;
        if (++counter.failures < threshold) {
            return Optional.empty();
        }
        counter.failures = 0;
        counter.lastLock = counter.lastLock == null ? limits.base()
            : java.util.Collections.min(java.util.List.of(counter.lastLock.multipliedBy(2), MAX_LOCK));
        counter.lockedUntil = now.plus(counter.lastLock);
        return Optional.of(counter.lockedUntil);
    }

    private void prune(Instant now) {
        for (var map : java.util.List.of(pairs, accounts)) {
            // Un bloqueo dura como mucho 24 h desde su último fallo: lo viejo ya no está bloqueado
            map.values().removeIf(c -> stale(c, now));
        }
    }

    private static boolean stale(Counter counter, Instant now) {
        return Duration.between(counter.lastFailure, now).compareTo(FORGET_AFTER) > 0;
    }

    private static Optional<Instant> locked(Counter counter, Instant now) {
        return counter != null && counter.lockedUntil.isAfter(now) ? Optional.of(counter.lockedUntil) : Optional.empty();
    }

    private static Optional<Instant> latest(Optional<Instant> a, Optional<Instant> b) {
        if (a.isEmpty()) {
            return b;
        }
        return b.isPresent() && b.get().isAfter(a.get()) ? b : a;
    }

    private static String key(String account) {
        return account.toLowerCase(Locale.ROOT);
    }

    private static String pair(String account, String ip) {
        return key(account) + "\n" + ip;
    }
}
