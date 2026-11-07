package dev.sam.common.proto.account;

import java.util.List;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:totp_enroll}, servidor → cliente (PROTOCOLO.md 5.7): la URI del QR y los códigos de
 * respaldo. Lleva el secreto: solo viaja por el TLS de SAM y el cliente no lo guarda.
 */
public record TotpEnroll(String uri, List<String> backupCodes) {

    public static final String ID = "totp_enroll";

    private static final int MAX_URI = 512;
    private static final int MAX_CODES = 10;

    public TotpEnroll {
        if (!uri.startsWith("otpauth://totp/")) {
            throw new IllegalArgumentException("la URI del 2FA debe ser otpauth://totp/");
        }
        backupCodes = List.copyOf(backupCodes);
    }

    public void write(SamWriter out) {
        out.string(uri, MAX_URI).list(backupCodes, MAX_CODES, (w, code) -> w.string(code, AccountInfo.MAX_CODE));
    }

    public static TotpEnroll read(SamReader in) {
        var uri = in.string(MAX_URI);
        var codes = in.list(MAX_CODES, r -> r.string(AccountInfo.MAX_CODE));
        return ProtocolException.fromRead(() -> new TotpEnroll(uri, codes));
    }
}
