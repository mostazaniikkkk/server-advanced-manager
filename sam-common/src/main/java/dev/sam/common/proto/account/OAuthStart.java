package dev.sam.common.proto.account;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:oauth_start}, cliente → servidor (PROTOCOLO.md 5.4): el proveedor y el puerto loopback que
 * el cliente ya abrió para recibir el redirect. Como mucho {@value #MAX_BYTES} bytes.
 */
public record OAuthStart(OAuthProvider provider, int port) {

    public static final String ID = "oauth_start";
    public static final int MAX_BYTES = 16;

    private static final int MAX_PORT = 65535;

    public OAuthStart {
        if (port < 1 || port > MAX_PORT) {
            throw new IllegalArgumentException("puerto " + port + " fuera de 1.." + MAX_PORT);
        }
    }

    public void write(SamWriter out) {
        out.enumValue(provider).varInt(port);
    }

    public static OAuthStart read(SamReader in) {
        var provider = in.enumValue(OAuthProvider.class);
        var port = in.varInt();
        return ProtocolException.fromRead(() -> new OAuthStart(provider, port));
    }
}
