package dev.sam.common.proto.account;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/** {@code sam:totp_confirm}, cliente → servidor (PROTOCOLO.md 5.7): el primer código de la app lo activa. */
public record TotpConfirm(String code) {

    public static final String ID = "totp_confirm";
    public static final int MAX_BYTES = 512;

    public void write(SamWriter out) {
        out.string(code, AccountInfo.MAX_CODE);
    }

    public static TotpConfirm read(SamReader in) {
        return new TotpConfirm(in.string(AccountInfo.MAX_CODE));
    }
}
