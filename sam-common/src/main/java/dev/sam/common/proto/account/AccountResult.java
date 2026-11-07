package dev.sam.common.proto.account;

import java.util.Optional;

import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:account_result}, servidor → cliente (PROTOCOLO.md 5.7): el resultado de una operación de
 * cuenta. {@code detail} es texto genérico.
 */
public record AccountResult(Status status, Optional<String> detail) {

    public static final String ID = "account_result";

    private static final int MAX_DETAIL = 128;

    public enum Status {
        OK, FAILED, LOCKED
    }

    public void write(SamWriter out) {
        out.enumValue(status).optional(detail, (w, d) -> w.string(d, MAX_DETAIL));
    }

    public static AccountResult read(SamReader in) {
        var status = in.enumValue(Status.class);
        return new AccountResult(status, in.optional(r -> r.string(MAX_DETAIL)));
    }
}
