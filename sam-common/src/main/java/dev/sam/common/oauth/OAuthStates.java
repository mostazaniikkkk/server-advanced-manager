package dev.sam.common.oauth;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.WeakHashMap;

/**
 * Los flujos OAuth abiertos (RS-OAUTH-03, RN-22): cada {@code state} es de un solo uso, vence en
 * {@link #TTL} y queda atado a la conexión que lo pidió y a su cuenta. Una conexión tiene como mucho uno
 * abierto: pedir otro descarta el anterior.
 */
public final class OAuthStates {

    public static final Duration TTL = Duration.ofMinutes(5);

    /** Para qué se abrió: entrar con Google o vincularlo desde "Opciones de cuenta". */
    public enum Purpose {
        LOGIN, LINK
    }

    public record Pending(String state, String nonce, Pkce pkce, String nick, Purpose purpose, String redirectUri) {
    }

    private record Entry(Pending pending, Instant expires) {
    }

    private final SecureRandom random;
    private final Clock clock;
    /** Por conexión; si la conexión se pierde sin avisar, su entrada no la retiene. */
    private final Map<Object, Entry> open = new WeakHashMap<>();

    public OAuthStates(SecureRandom random, Clock clock) {
        this.random = random;
        this.clock = clock;
    }

    public synchronized Pending issue(Object connection, String nick, Purpose purpose, String redirectUri) {
        var pending = new Pending(Pkce.randomToken(random), Pkce.randomToken(random), Pkce.create(random), nick, purpose, redirectUri);
        open.put(connection, new Entry(pending, clock.instant().plus(TTL)));
        return pending;
    }

    /** El flujo abierto de esta conexión con ese {@code state}, si no venció. Siempre lo cierra. */
    public synchronized Optional<Pending> consume(Object connection, String state) {
        var entry = open.get(connection);
        if (entry == null || !entry.pending().state().equals(state)) {
            return Optional.empty();
        }
        open.remove(connection);
        return clock.instant().isAfter(entry.expires()) ? Optional.empty() : Optional.of(entry.pending());
    }

    public synchronized void forget(Object connection) {
        open.remove(connection);
    }
}
