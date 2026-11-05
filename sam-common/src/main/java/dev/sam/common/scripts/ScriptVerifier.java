package dev.sam.common.scripts;

import java.security.MessageDigest;
import java.util.Collection;
import java.util.HexFormat;
import java.util.Map;

/**
 * Verificación de un script contra las claves de confianza (RS-SIG-01, PROTOCOLO.md 8.2).
 * La usan el servidor al cargar los datapacks y el cliente en cada carga desde su caché (RN-31).
 */
public final class ScriptVerifier {

    public enum Reason {
        /** No hay {@code signature.json} en la raíz. */
        MISSING_SIGNATURE,
        /** {@code signature.json} no pasa la lectura estricta. */
        MALFORMED_SIGNATURE,
        /** Rutas inválidas, demasiados archivos o script vacío. */
        INVALID_FILES,
        /** El {@code key_id} no corresponde a ninguna clave de confianza. */
        UNKNOWN_KEY,
        /** Los archivos no coinciden con el lockfile firmado (alguno se agregó, quitó o modificó). */
        LOCK_MISMATCH,
        /** La firma no es válida con la clave de confianza indicada. */
        BAD_SIGNATURE
    }

    public sealed interface Result {
        record Valid(KeyId keyId, String lockSha256) implements Result {
        }

        record Invalid(Reason reason) implements Result {
        }
    }

    private ScriptVerifier() {
    }

    /**
     * @param files       todos los archivos del script, incluido su {@code signature.json}
     * @param trustedKeys claves de confianza (trust store del servidor o keylist en el cliente)
     */
    public static Result verify(Map<String, byte[]> files, Collection<SigningPublicKey> trustedKeys) {
        var signatureJson = files.get(Lockfile.SIGNATURE_FILE);
        if (signatureJson == null) {
            return new Result.Invalid(Reason.MISSING_SIGNATURE);
        }
        ScriptSignature signature;
        try {
            signature = ScriptSignature.parse(signatureJson);
        } catch (IllegalArgumentException e) {
            return new Result.Invalid(Reason.MALFORMED_SIGNATURE);
        }
        Lockfile lock;
        try {
            lock = Lockfile.of(files);
        } catch (IllegalArgumentException e) {
            return new Result.Invalid(Reason.INVALID_FILES);
        }
        var key = trustedKeys.stream().filter(k -> k.keyId().equals(signature.keyId())).findFirst();
        if (key.isEmpty()) {
            return new Result.Invalid(Reason.UNKNOWN_KEY);
        }
        var lockSha = lock.sha256();
        if (!MessageDigest.isEqual(lockSha, signature.lockSha256())) {
            return new Result.Invalid(Reason.LOCK_MISMATCH);
        }
        if (!key.get().verify(ScriptSigner.signedMessage(lockSha), signature.signature())) {
            return new Result.Invalid(Reason.BAD_SIGNATURE);
        }
        return new Result.Valid(signature.keyId(), HexFormat.of().formatHex(lockSha));
    }
}
