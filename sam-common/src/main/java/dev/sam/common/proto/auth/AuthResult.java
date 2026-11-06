package dev.sam.common.proto.auth;

import java.util.Optional;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * {@code sam:auth_result}, servidor → cliente (PROTOCOLO.md 5.3). {@code FAILED} es el mismo para
 * cualquier causa (RS-AUTH-05) y {@code detail} es texto genérico.
 */
public record AuthResult(Status status, Optional<Integer> retryAfterSeconds, Optional<String> detail) {

    public static final String ID = "auth_result";

    private static final int MAX_DETAIL = 128;

    public enum Status {
        OK, FAILED, LOCKED, NEED_TOTP, NEED_ENROLL, NEED_EMAIL_VERIFY, RECOVERY_PENDING, RECOVERY_SENT
    }

    public AuthResult {
        if (retryAfterSeconds.isPresent() && retryAfterSeconds.get() < 0) {
            throw new IllegalArgumentException("retry_after negativo");
        }
    }

    public void write(SamWriter out) {
        out.enumValue(status).optional(retryAfterSeconds, SamWriter::varInt).optional(detail, (w, d) -> w.string(d, MAX_DETAIL));
    }

    public static AuthResult read(SamReader in) {
        var status = in.enumValue(Status.class);
        var retryAfter = in.optional(SamReader::varInt);
        var detail = in.optional(r -> r.string(MAX_DETAIL));
        return ProtocolException.fromRead(() -> new AuthResult(status, retryAfter, detail));
    }
}
