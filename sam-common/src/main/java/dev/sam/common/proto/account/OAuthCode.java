package dev.sam.common.proto.account;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:oauth_code}, cliente → servidor (PROTOCOLO.md 5.4): el {@code code} que llegó al loopback y
 * su {@code state}. Como mucho {@value #MAX_BYTES} bytes (5.6).
 */
public record OAuthCode(String code, String state) {

    public static final String ID = "oauth_code";
    public static final int MAX_BYTES = 1536;

    private static final int MAX_CODE = 1024;
    private static final int MAX_STATE = 128;

    public void write(SamWriter out) {
        out.string(code, MAX_CODE).string(state, MAX_STATE);
    }

    public static OAuthCode read(SamReader in) {
        var code = in.string(MAX_CODE);
        return new OAuthCode(code, in.string(MAX_STATE));
    }
}
