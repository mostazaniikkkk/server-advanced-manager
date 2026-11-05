package dev.sam.common.net.gate;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

import dev.sam.common.net.ip.ClientIp;
import io.netty.channel.Channel;
import io.netty.util.AttributeKey;

/**
 * Límite de conexiones sin clasificar (PROTOCOLO.md 10) y en handshake WebSocket (RS-WS-03): por
 * IP y en total. Una conexión ocupa un lugar desde que entra a la compuerta hasta que se clasifica
 * (TLS o vanilla) o se cierra; si el lugar no está disponible, el llamador cierra en el acto.
 *
 * <p>Las IP compartidas (proxies de confianza, RS-WS-02) no cuentan por IP: cuentan solo en el
 * total y, en el handshake WebSocket, el lugar pasa a la IP real ({@link #attribute}).
 *
 * <p>Las conexiones llegan por varios event loops: el conteo se sincroniza sobre el guardia.
 */
public final class ConnectionGuard {

    public static final int DEFAULT_PER_IP = 8;
    public static final int DEFAULT_GLOBAL = 256;

    static final AttributeKey<Permit> PERMIT = AttributeKey.valueOf("sam_ingress_permit");

    private final int perIp;
    private final int global;
    private final Predicate<InetAddress> sharedAddress;
    private final Map<InetAddress, Integer> byIp = new HashMap<>();
    private int total;

    /**
     * @param sharedAddress IP que no cuentan por IP (proxies de confianza)
     * @throws IllegalArgumentException si algún límite no es positivo
     */
    public ConnectionGuard(int perIp, int global, Predicate<InetAddress> sharedAddress) {
        if (perIp < 1 || global < 1) {
            throw new IllegalArgumentException("los límites de conexiones deben ser positivos");
        }
        this.perIp = perIp;
        this.global = global;
        this.sharedAddress = sharedAddress;
    }

    /** Sin límites (tests y rutas internas): igual registra y libera lugares. */
    public static ConnectionGuard unlimited() {
        return new ConnectionGuard(Integer.MAX_VALUE, Integer.MAX_VALUE, address -> true);
    }

    /**
     * Reserva un lugar para la conexión; si ya tiene uno (la compuerta interna del WebSocket), lo
     * conserva. Se libera solo al cerrarse, si nadie lo liberó antes.
     *
     * @return {@code false} si se excede un límite
     */
    public boolean admit(Channel channel) {
        var slot = channel.attr(PERMIT);
        if (slot.get() != null) {
            return true;
        }
        var permit = reserve(ClientIp.of(channel).filter(sharedAddress.negate()).orElse(null));
        if (permit == null) {
            return false;
        }
        slot.set(permit);
        channel.closeFuture().addListener(closed -> permit.release());
        return true;
    }

    /** La conexión se clasificó: deja de contar. Idempotente. */
    public static void release(Channel channel) {
        var permit = channel.attr(PERMIT).getAndSet(null);
        if (permit != null) {
            permit.release();
        }
    }

    /**
     * La IP real de la conexión ya se conoce (RS-WS-02): su lugar pasa a contar para esa IP.
     *
     * @return {@code false} si esa IP ya no tiene lugares: el llamador cierra
     */
    public static boolean attribute(Channel channel, InetAddress realIp) {
        var permit = channel.attr(PERMIT).get();
        return permit == null || permit.guard().move(permit, realIp);
    }

    /** @param ip {@code null} si no cuenta por IP; count(null) es 0 porque nunca se registra */
    private synchronized Permit reserve(InetAddress ip) {
        if (total >= global || count(ip) >= perIp) {
            return null;
        }
        total++;
        adjust(ip, 1);
        return new Permit(ip);
    }

    private synchronized void release(Permit permit) {
        if (!permit.released) {
            permit.released = true;
            total--;
            adjust(permit.ip, -1);
        }
    }

    private synchronized boolean move(Permit permit, InetAddress realIp) {
        var target = sharedAddress.test(realIp) ? null : realIp;
        if (permit.released || Objects.equals(target, permit.ip)) {
            return true;
        }
        if (count(target) >= perIp) {
            return false;
        }
        adjust(permit.ip, -1);
        adjust(target, 1);
        permit.ip = target;
        return true;
    }

    synchronized int pending() {
        return total;
    }

    synchronized int pending(InetAddress ip) {
        return count(ip);
    }

    /** IP con conexiones pendientes: no crece con IP que ya se fueron. */
    synchronized int trackedIps() {
        return byIp.size();
    }

    private int count(InetAddress ip) {
        return byIp.getOrDefault(ip, 0);
    }

    /** Suma {@code delta} a la cuenta de {@code ip}; al llegar a cero la quita. */
    private void adjust(InetAddress ip, int delta) {
        if (ip != null) {
            byIp.merge(ip, delta, (current, change) -> current + change == 0 ? null : current + change);
        }
    }

    /** El lugar de una conexión. {@code ip} es {@code null} si no cuenta por IP. Lo protege el guardia. */
    final class Permit {
        private InetAddress ip;
        private boolean released;

        private Permit(InetAddress ip) {
            this.ip = ip;
        }

        ConnectionGuard guard() {
            return ConnectionGuard.this;
        }

        void release() {
            ConnectionGuard.this.release(this);
        }
    }
}
