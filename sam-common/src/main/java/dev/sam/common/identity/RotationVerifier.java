package dev.sam.common.identity;

import java.util.List;

/**
 * Resuelve una cadena de rotaciones firmadas desde la clave fijada hasta la presentada en el TLS
 * (PROTOCOLO.md 3.7). Función pura.
 */
public final class RotationVerifier {

    /** Máximo de declaraciones que el servidor puede enviar en {@code sam:hello}. */
    public static final int MAX_STATEMENTS = 4;

    public enum Reason {
        /** No hay cadena desde la clave fijada hasta la presentada (o hay un ciclo). */
        NO_PATH,
        /** Una declaración del camino tiene la firma inválida: se rechaza todo. */
        INVALID_SIGNATURE,
        /** Más de {@link #MAX_STATEMENTS} declaraciones. */
        TOO_MANY_STATEMENTS
    }

    public sealed interface Result {
        record Rotated(ServerPublicKey newKey, int chainLength) implements Result {
        }

        record Rejected(Reason reason) implements Result {
        }
    }

    private RotationVerifier() {
    }

    /**
     * @throws IllegalArgumentException si la clave presentada es la fijada (no es una rotación)
     */
    public static Result resolve(PinnedServer pinned, ServerPublicKey presented, List<RotationStatement> statements) {
        if (presented.equals(pinned.key())) {
            throw new IllegalArgumentException("La clave presentada es la fijada: no hay rotación que resolver");
        }
        if (statements.size() > MAX_STATEMENTS) {
            return new Result.Rejected(Reason.TOO_MANY_STATEMENTS);
        }
        // Cada paso consume una declaración: con como máximo statements.size() pasos, un ciclo
        // (A → B → A) no puede recorrerse para siempre.
        var current = pinned.key();
        for (int step = 1; step <= statements.size(); step++) {
            var from = current;
            var next = statements.stream()
                .filter(s -> s.serverId().equals(pinned.id()) && s.oldPin().equals(from.pin()))
                .findFirst();
            if (next.isEmpty()) {
                return new Result.Rejected(Reason.NO_PATH);
            }
            if (!next.get().isSignedBy(from)) {
                return new Result.Rejected(Reason.INVALID_SIGNATURE);
            }
            current = next.get().newKey();
            if (current.equals(presented)) {
                return new Result.Rotated(current, step);
            }
        }
        return new Result.Rejected(Reason.NO_PATH);
    }
}
