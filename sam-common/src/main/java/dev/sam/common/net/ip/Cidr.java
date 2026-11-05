package dev.sam.common.net.ip;

import java.net.InetAddress;

/**
 * Un rango CIDR IPv4 o IPv6. Estricto: la dirección debe ser la de la red (sin bits de host), para
 * que un {@code 10.0.0.1/8} escrito por error no se lea distinto de lo que el operador cree.
 */
public final class Cidr {

    private final byte[] network;
    private final int prefix;

    private Cidr(byte[] network, int prefix) {
        this.network = network;
        this.prefix = prefix;
    }

    /** @throws IllegalArgumentException citando {@code text} si no es un CIDR válido */
    public static Cidr parse(String text) {
        var parts = text.split("/", -1);
        if (parts.length != 2) {
            throw invalid(text, "debe ser dirección/prefijo");
        }
        var address = IpLiteral.parse(parts[0])
            .orElseThrow(() -> invalid(text, "la dirección no es una IP"))
            .getAddress();
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw invalid(text, "el prefijo no es un número");
        }
        var bits = address.length * Byte.SIZE;
        if (prefix < 0 || prefix > bits) {
            throw invalid(text, "el prefijo debe estar entre 0 y " + bits);
        }
        for (int bit = prefix; bit < bits; bit++) {
            if (bitAt(address, bit)) {
                throw invalid(text, "la dirección tiene bits fuera del prefijo");
            }
        }
        return new Cidr(address, prefix);
    }

    /** Las IPv4 y las IPv6 nunca se mezclan. */
    public boolean contains(InetAddress address) {
        var bytes = address.getAddress();
        if (bytes.length != network.length) {
            return false;
        }
        for (int bit = 0; bit < prefix; bit++) {
            if (bitAt(bytes, bit) != bitAt(network, bit)) {
                return false;
            }
        }
        return true;
    }

    private static boolean bitAt(byte[] bytes, int bit) {
        return (bytes[bit / Byte.SIZE] & (0x80 >>> (bit % Byte.SIZE))) != 0;
    }

    private static IllegalArgumentException invalid(String text, String reason) {
        return new IllegalArgumentException("CIDR inválido \"" + text + "\": " + reason);
    }
}
