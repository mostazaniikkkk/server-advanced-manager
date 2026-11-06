package dev.sam.common.proto.auth;

import java.util.List;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/** Lo que el cliente necesita para dibujar la AuthScreen (PROTOCOLO.md 5.3). */
public record AuthPolicyView(List<AuthMethod> methods, boolean requireTotp, boolean mustEnroll, EmailVerify emailVerify,
        int minPassword) {

    private static final int MAX_METHODS = AuthMethod.values().length;
    private static final int MAX_MIN_PASSWORD = 128;

    public AuthPolicyView {
        if (minPassword < 0 || minPassword > MAX_MIN_PASSWORD) {
            throw new IllegalArgumentException("min_password " + minPassword + " fuera de 0.." + MAX_MIN_PASSWORD);
        }
        methods = List.copyOf(methods);
    }

    void write(SamWriter out) {
        out.list(methods, MAX_METHODS, SamWriter::enumValue).bool(requireTotp).bool(mustEnroll).enumValue(emailVerify)
            .varInt(minPassword);
    }

    static AuthPolicyView read(SamReader in) {
        var methods = in.list(MAX_METHODS, r -> r.enumValue(AuthMethod.class));
        var requireTotp = in.bool();
        var mustEnroll = in.bool();
        var emailVerify = in.enumValue(EmailVerify.class);
        var minPassword = in.varInt();
        return ProtocolException.fromRead(() -> new AuthPolicyView(methods, requireTotp, mustEnroll, emailVerify, minPassword));
    }
}
