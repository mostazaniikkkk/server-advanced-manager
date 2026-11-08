package dev.sam.common.proto.account;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/** {@code sam:account_export}, servidor → cliente (PROTOCOLO.md 5.7, RF-AUTH-07e): los datos del jugador en JSON. */
public record AccountExport(String json) {

    public static final String ID = "account_export";
    public static final int MAX_JSON = 65536;
    /** El JSON (como mucho {@value #MAX_JSON} bytes en UTF-8) más su largo. */
    public static final int MAX_BYTES = MAX_JSON + 8;

    public void write(SamWriter out) {
        out.string(json, MAX_JSON);
    }

    public static AccountExport read(SamReader in) {
        return new AccountExport(in.string(MAX_JSON));
    }
}
