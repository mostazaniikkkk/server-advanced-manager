package dev.sam.common.net.ip;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Optional;

import io.netty.channel.Channel;
import io.netty.util.AttributeKey;

/**
 * La IP del cliente de una conexión (RS-WS-02): la resuelta en el handshake WebSocket si la hubo,
 * si no la del socket. Es la que usan bans, límites y auditoría.
 */
public final class ClientIp {

    static final AttributeKey<InetAddress> RESOLVED = AttributeKey.valueOf("sam_client_ip");

    private ClientIp() {
    }

    public static Optional<InetAddress> of(Channel channel) {
        var resolved = channel.attr(RESOLVED).get();
        return resolved != null ? Optional.of(resolved) : socket(channel);
    }

    /** Vacío si el canal no es de red (o la dirección no está resuelta). */
    static Optional<InetAddress> socket(Channel channel) {
        return channel.remoteAddress() instanceof InetSocketAddress address
            ? Optional.ofNullable(address.getAddress())
            : Optional.empty();
    }
}
