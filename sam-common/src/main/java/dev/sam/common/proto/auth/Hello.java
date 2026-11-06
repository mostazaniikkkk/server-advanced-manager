package dev.sam.common.proto.auth;

import java.util.List;

import dev.sam.common.identity.ServerId;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:hello}, servidor → cliente (PROTOCOLO.md 5.1). La lista {@code rotation} (3.7) se agrega
 * con la rotación del certificado.
 */
public record Hello(ProtocolVersion protocol, ServerId serverId, String serverName, List<String> features,
        AccountState accountState, AuthPolicyView policy) {

    public static final String ID = "hello";

    private static final int MAX_NAME = 64;
    private static final int MAX_FEATURES = 32;
    private static final int MAX_FEATURE = 32;

    public Hello {
        features = List.copyOf(features);
    }

    public void write(SamWriter out) {
        protocol.write(out);
        out.fixed(serverId.toBytes(), ServerId.LENGTH).string(serverName, MAX_NAME)
            .list(features, MAX_FEATURES, (w, feature) -> w.string(feature, MAX_FEATURE)).enumValue(accountState);
        policy.write(out);
    }

    public static Hello read(SamReader in) {
        var protocol = ProtocolVersion.read(in);
        var serverId = ServerId.of(in.fixed(ServerId.LENGTH));
        var serverName = in.string(MAX_NAME);
        var features = in.list(MAX_FEATURES, r -> r.string(MAX_FEATURE));
        var accountState = in.enumValue(AccountState.class);
        return new Hello(protocol, serverId, serverName, features, accountState, AuthPolicyView.read(in));
    }
}
