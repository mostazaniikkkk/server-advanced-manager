package dev.sam.common.scripts;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * El trust store de scripts del servidor (RS-SIG-02/03/06). Las claves públicas de firma están en
 * {@code keys/trusted/*.pub} (base64 de los 32 bytes Ed25519; las líneas con {@code #} son comentarios).
 * Una clave solo está activa si su {@code key_id} figura en {@code keys/confirmed.txt}, que escribe el
 * comando de consola {@code sam scripts trust confirm}: una clave agregada por alguien con acceso a los
 * archivos no se activa sola. Quitar el {@code .pub} la revoca.
 */
public record TrustStore(List<KeyList.Entry> entries, List<Pending> pending, List<String> problems) {

    static final String TRUSTED = "trusted";
    static final String CONFIRMED = "confirmed.txt";

    /** Una clave presente que todavía no se confirmó desde la consola. */
    public record Pending(KeyId keyId, String file) {
    }

    public TrustStore {
        entries = List.copyOf(entries);
        pending = List.copyOf(pending);
        problems = List.copyOf(problems);
    }

    /** @param keys la carpeta {@code config/sam/keys} */
    public static TrustStore load(Path keys) throws IOException {
        var confirmed = confirmed(keys);
        var active = new ArrayList<KeyList.Entry>();
        var pending = new ArrayList<Pending>();
        var problems = new ArrayList<String>();
        var trusted = keys.resolve(TRUSTED);
        if (!Files.isDirectory(trusted)) {
            return new TrustStore(active, pending, problems);
        }
        List<Path> files;
        try (var listing = Files.list(trusted)) {
            files = listing.filter(f -> f.getFileName().toString().endsWith(".pub")).sorted().toList();
        }
        for (var file : files) {
            var name = file.getFileName().toString();
            var key = parsePublic(Files.readString(file));
            if (key.isEmpty()) {
                problems.add(name + ": no es una clave pública Ed25519 en base64");
            } else if (confirmed.contains(key.get().keyId().hex())) {
                active.add(new KeyList.Entry(key.get(), label(name)));
            } else {
                pending.add(new Pending(key.get().keyId(), name));
            }
        }
        return new TrustStore(active, pending, problems);
    }

    /** Las claves activas (confirmadas). */
    public List<SigningPublicKey> active() {
        return entries.stream().map(KeyList.Entry::key).toList();
    }

    /** El nombre del archivo sin {@code .pub}, acotado a lo que cabe en la keylist sin cortar un carácter. */
    private static String label(String file) {
        var label = file.substring(0, file.length() - ".pub".length());
        while (label.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > KeyList.MAX_LABEL) {
            label = label.substring(0, label.offsetByCodePoints(label.length(), -1));
        }
        return label;
    }

    /**
     * Confirma una clave pendiente (solo desde la consola real del servidor, RS-ADM-01).
     *
     * @return {@code true} si estaba pendiente y quedó activa
     */
    public static boolean confirm(Path keys, KeyId keyId) throws IOException {
        var store = load(keys);
        if (store.pending().stream().noneMatch(p -> p.keyId().equals(keyId))) {
            return false;
        }
        var file = keys.resolve(CONFIRMED);
        var before = Files.exists(file) ? Files.readString(file) : "";
        dev.sam.common.config.SecureFiles.writeString(file, before + keyId.hex() + "\n");
        return true;
    }

    private static java.util.Set<String> confirmed(Path keys) throws IOException {
        var file = keys.resolve(CONFIRMED);
        var lines = Files.exists(file) ? Files.readAllLines(file) : List.<String>of();
        return lines.stream().map(String::strip).collect(Collectors.toSet());
    }

    /** El contenido de un {@code .pub}: la primera línea que no es comentario, en base64 (también lo usa sam-signer). */
    public static Optional<SigningPublicKey> parsePublic(String content) {
        var line = content.lines().map(String::strip).filter(l -> !l.isEmpty() && !l.startsWith("#")).findFirst().orElse("");
        try {
            return Optional.of(SigningPublicKey.of(Base64.getDecoder().decode(line)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
