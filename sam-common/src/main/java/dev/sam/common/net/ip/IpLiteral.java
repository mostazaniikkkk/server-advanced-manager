package dev.sam.common.net.ip;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;

import io.netty.util.NetUtil;

/** Interpreta una IP escrita como texto <b>sin consultar DNS</b>: un nombre de host no es una IP. */
final class IpLiteral {

    private IpLiteral() {
    }

    static Optional<InetAddress> parse(String text) {
        var bytes = NetUtil.createByteArrayFromIpAddressString(text);
        if (bytes == null) {
            return Optional.empty();
        }
        try {
            // Con bytes, la JDK no resuelve nada; una IPv6 mapeada (::ffff:a.b.c.d) queda como IPv4
            return Optional.of(InetAddress.getByAddress(bytes));
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Netty devolvió una IP de largo inválido", e);
        }
    }
}
