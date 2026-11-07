package dev.sam.common.proto.account;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:oauth_url}, servidor → cliente (PROTOCOLO.md 5.4): la URL de autorización que el cliente
 * abre en el navegador del sistema. Solo https: el cliente nunca abre otro esquema.
 */
public record OAuthUrl(String url) {

    public static final String ID = "oauth_url";

    private static final int MAX_URL = 2048;

    public OAuthUrl {
        if (!url.startsWith("https://")) {
            throw new IllegalArgumentException("la URL de OAuth debe ser https");
        }
    }

    public void write(SamWriter out) {
        out.string(url, MAX_URL);
    }

    public static OAuthUrl read(SamReader in) {
        var url = in.string(MAX_URL);
        return ProtocolException.fromRead(() -> new OAuthUrl(url));
    }
}
