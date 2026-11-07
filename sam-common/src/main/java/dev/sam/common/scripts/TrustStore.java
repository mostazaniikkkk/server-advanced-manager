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
public record TrustStore(List<SigningPublicKey> active, List<Pending> pending, List<String> problems) {

    static final String TRUSTED = "trusted";
    static final String CONFIRMED = "confirmed.txt";

    /** Una clave presente que todavía no se confirmó desde la consola. */
    public record Pending(KeyId keyId, String file) {
    }

    public TrustStore {
        active = List.copyOf(active);
        pending = List.copyOf(pending);
        problems = List.copyOf(problems);
    }

    /** @param keys la carpeta {@code config/sam/keys} */
    public static TrustStore load(Path keys) throws IOException {
        var confirmed = confirmed(keys);
        var active = new ArrayList<SigningPublicKey>();
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
            var key = parse(Files.readString(file));
            if (key.isEmpty()) {
                problems.add(name + ": no es una clave pública Ed25519 en base64");
            } else if (confirmed.contains(key.get().keyId().hex())) {
                active.add(key.get());
            } else {
                pending.add(new Pending(key.get().keyId(), name));
            }
        }
        return new TrustStore(active, pending, problems);
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
        Files.writeString(keys.resolve(CONFIRMED), keyId.hex() + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        return true;
    }

    private static java.util.Set<String> confirmed(Path keys) throws IOException {
        var file = keys.resolve(CONFIRMED);
        var lines = Files.exists(file) ? Files.readAllLines(file) : List.<String>of();
        return lines.stream().map(String::strip).collect(Collectors.toSet());
    }

    private static Optional<SigningPublicKey> parse(String content) {
        var line = content.lines().map(String::strip).filter(l -> !l.isEmpty() && !l.startsWith("#")).findFirst().orElse("");
        try {
            return Optional.of(SigningPublicKey.of(Base64.getDecoder().decode(line)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
