package dev.sam.common.scripts;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Contenido de {@code signature.json} (PROTOCOLO.md 8.2).
 *
 * <p>Forma canónica (la que escribe {@link #toJson()}):
 * <pre>{"format":"sam-sig-v1","key_id":"…","lock_sha256":"…","signature":"…"}\n</pre>
 *
 * <p>Lectura <b>estricta</b>, por ser un archivo de seguridad: hasta 512 bytes ASCII, un objeto
 * plano con exactamente esas 4 claves de tipo string, sin duplicados (un lector podría quedarse
 * con la primera y otro con la última), sin escapes y con base64 canónico.
 */
public record ScriptSignature(KeyId keyId, byte[] lockSha256, byte[] signature) {

    public static final String FORMAT = "sam-sig-v1";
    public static final int MAX_BYTES = 512;
    private static final int LOCK_LENGTH = 32;
    private static final int SIGNATURE_LENGTH = 64;
    private static final Set<String> KEYS = Set.of("format", "key_id", "lock_sha256", "signature");

    /** Espacio en blanco de JSON (RFC 8259): solo espacio, tab, LF y CR. Ojo: el \s de Java acepta además \f y \x0B. */
    private static final String WS = "[ \\t\\n\\r]*";
    /** Contenido de un string: ASCII imprimible sin comillas ni barra invertida (sin escapes). */
    private static final String CHARS = "[\\x20\\x21\\x23-\\x5B\\x5D-\\x7E]*";
    private static final String PAIR = "\"" + CHARS + "\"" + WS + ":" + WS + "\"" + CHARS + "\"";
    private static final Pattern DOCUMENT = Pattern.compile(WS + "\\{" + WS + PAIR + "(?:" + WS + "," + WS + PAIR + ")*" + WS + "\\}" + WS);
    private static final Pattern PAIR_PARTS = Pattern.compile("\"(" + CHARS + ")\"" + WS + ":" + WS + "\"(" + CHARS + ")\"");
    private static final Pattern LOCK_HEX = Pattern.compile("[0-9a-f]{64}");

    public ScriptSignature {
        Objects.requireNonNull(keyId, "keyId");
        if (lockSha256.length != LOCK_LENGTH) {
            throw new IllegalArgumentException("lock_sha256 debe medir " + LOCK_LENGTH + " bytes");
        }
        if (signature.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("La firma debe medir " + SIGNATURE_LENGTH + " bytes");
        }
        lockSha256 = lockSha256.clone();
        signature = signature.clone();
    }

    public static ScriptSignature parse(byte[] json) {
        if (json.length > MAX_BYTES) {
            throw invalid("supera los " + MAX_BYTES + " bytes");
        }
        // Un byte no ASCII se decodifica como U+FFFD, que ninguna clase de la gramática admite
        var text = new String(json, StandardCharsets.US_ASCII);
        if (!DOCUMENT.matcher(text).matches()) {
            throw invalid("no es un objeto plano de strings ASCII sin escapes");
        }
        var fields = new LinkedHashMap<String, String>();
        var pairs = PAIR_PARTS.matcher(text);
        while (pairs.find()) {
            if (fields.put(pairs.group(1), pairs.group(2)) != null) {
                throw invalid("clave duplicada \"" + pairs.group(1) + "\"");
            }
        }
        if (!fields.keySet().equals(KEYS)) {
            throw invalid("se esperan exactamente las claves " + KEYS);
        }
        if (!fields.get("format").equals(FORMAT)) {
            throw invalid("formato desconocido \"" + fields.get("format") + "\"");
        }
        return new ScriptSignature(parseKeyId(fields.get("key_id")), parseLock(fields.get("lock_sha256")),
            parseSignature(fields.get("signature")));
    }

    /** Forma canónica, terminada en salto de línea. */
    public byte[] toJson() {
        var json = "{\"format\":\"" + FORMAT + "\",\"key_id\":\"" + keyId.hex()
            + "\",\"lock_sha256\":\"" + HexFormat.of().formatHex(lockSha256)
            + "\",\"signature\":\"" + Base64.getEncoder().encodeToString(signature) + "\"}\n";
        return json.getBytes(StandardCharsets.US_ASCII);
    }

    @Override
    public byte[] lockSha256() {
        return lockSha256.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ScriptSignature that
            && keyId.equals(that.keyId)
            && Arrays.equals(lockSha256, that.lockSha256)
            && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, Arrays.hashCode(lockSha256), Arrays.hashCode(signature));
    }

    @Override
    public String toString() {
        return "ScriptSignature[key_id=" + keyId + ", lock_sha256=" + HexFormat.of().formatHex(lockSha256) + "]";
    }

    private static KeyId parseKeyId(String value) {
        try {
            return KeyId.of(value);
        } catch (IllegalArgumentException e) {
            throw invalid("key_id inválido");
        }
    }

    private static byte[] parseLock(String value) {
        if (!LOCK_HEX.matcher(value).matches()) {
            throw invalid("lock_sha256 debe ser 64 dígitos hex en minúsculas");
        }
        return HexFormat.of().parseHex(value);
    }

    private static byte[] parseSignature(String value) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw invalid("signature no es base64");
        }
        if (decoded.length != SIGNATURE_LENGTH || !Base64.getEncoder().encodeToString(decoded).equals(value)) {
            throw invalid("signature debe ser el base64 canónico de 64 bytes");
        }
        return decoded;
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException("signature.json inválido: " + reason);
    }
}
