package dev.sam.common.net.ip;

import java.net.InetAddress;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpHeaders;

/**
 * IP real del jugador (RS-WS-02, TRANSPORTE_WEBSOCKET.md 4.4). La cabecera configurada solo se
 * acepta si la IP del socket es un proxy de confianza. En cualquier otro caso se usa la del socket,
 * y cualquier cabecera de IP recibida se ignora y se audita: es un intento de falsificarla. Los
 * mensajes de auditoría no incluyen el valor recibido (lo controla el cliente).
 */
public final class RealIpResolver {

    private final TrustedProxies trusted;
    private final RealIpHeader header;
    private final IngressAudit audit;

    public RealIpResolver(TrustedProxies trusted, RealIpHeader header, IngressAudit audit) {
        this.trusted = trusted;
        this.header = header;
        this.audit = audit;
    }

    /** Sin proxies de confianza ni auditoría: siempre la IP del socket. */
    public static RealIpResolver direct() {
        return new RealIpResolver(TrustedProxies.none(), RealIpHeader.CF_CONNECTING_IP, IngressAudit.NONE);
    }

    public InetAddress resolve(InetAddress socket, HttpHeaders headers) {
        if (!trusted.contains(socket)) {
            for (var known : RealIpHeader.values()) {
                if (headers.contains(known.headerName())) {
                    audit.record("Cabecera " + known.headerName() + " ignorada: llegó desde " + socket.getHostAddress()
                        + ", que no es un proxy de confianza");
                    return socket;
                }
            }
            return socket;
        }
        var real = header.extract(headers.getAll(header.headerName()));
        if (real.isEmpty()) {
            audit.record("El proxy de confianza " + socket.getHostAddress() + " no envió una " + header.headerName()
                + " válida: se usa la IP del socket");
        }
        return real.orElse(socket);
    }

    /** Resuelve y deja la IP en la conexión ({@link ClientIp#of}). Sin IP de socket no hace nada. */
    public void apply(Channel channel, HttpHeaders headers) {
        ClientIp.socket(channel).ifPresent(socket -> channel.attr(ClientIp.RESOLVED).set(resolve(socket, headers)));
    }
}
