package dev.sam.common.audit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.InstantSource;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import dev.sam.common.config.SecureFiles;

/**
 * RF-AUTH-08 / RF-AUTH-08a (H-08 de HARDENING.md): auditoría encadenada por hash. Una línea JSON por evento;
 * cada una lleva el hash de la anterior y el suyo (SHA-256 de la línea hasta antes de {@code ,"hash"}). Borrar,
 * cambiar o reordenar líneas rompe la cadena; truncar el final se detecta contra un ancla anterior
 * ({@link #head()}), que el servidor muestra al arrancar. Seguro entre hilos.
 */
public final class AuditLog {

    private static final String ZEROS = "0".repeat(64);
    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");
    private static final String HASH_KEY = ",\"hash\":\"";
    /** {@code ,"hash":"} + 64 hex + {@code "}}. */
    private static final int SUFFIX = HASH_KEY.length() + 64 + 2;
    private static final DateTimeFormatter EXPORT_NAME = DateTimeFormatter.ofPattern("'audit-export-'yyyyMMdd-HHmmss'.jsonl'")
        .withZone(ZoneOffset.UTC);

    /** La última línea de la cadena: su número y su hash ({@code 0} y 64 ceros si está vacía). */
    public record Head(long seq, String hash) {
    }

    /** Resultado de {@link #verify}: sana con {@code lines} líneas, o rota en la línea {@code brokenAt}. */
    public record Verification(boolean ok, long lines, long brokenAt, String reason) {
        public static Verification ok(long lines) {
            return new Verification(true, lines, 0, "");
        }

        public static Verification broken(long at, String reason) {
            return new Verification(false, 0, at, reason);
        }
    }

    /** Una línea ya validada en su forma. */
    private record Entry(long seq, String prev, String hash, String prefix) {
    }

    private final Path file;
    private final InstantSource clock;
    private Head head;

    private AuditLog(Path file, InstantSource clock, Head head) {
        this.file = file;
        this.clock = clock;
        this.head = head;
    }

    /** Abre la cadena y continúa desde su última línea; si esa línea está rota, no sigue escribiendo encima. */
    public static AuditLog open(Path file, InstantSource clock) throws IOException {
        var lines = read(file);
        if (lines.isEmpty()) {
            return new AuditLog(file, clock, new Head(0, ZEROS));
        }
        var last = parse(lines.getLast());
        if (last == null || !last.hash().equals(sha256(last.prefix()))) {
            throw new IOException("la auditoría " + file + " termina en una línea rota: revísala con /sam audit verify");
        }
        return new AuditLog(file, clock, new Head(last.seq(), last.hash()));
    }

    public synchronized void append(String type, String actor, String ip, String detail) throws IOException {
        var seq = head.seq() + 1;
        var prefix = prefix(seq, clock.instant().toString(), type, actor, ip, detail, head.hash());
        var hash = sha256(prefix);
        var line = prefix + HASH_KEY + hash + "\"}\n";
        if (!Files.exists(file)) {
            SecureFiles.writeString(file, line);
        } else {
            Files.writeString(file, line, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        }
        head = new Head(seq, hash);
    }

    /** Cuántas IPs se borraron y la cabeza de la cadena antes y después (RF-AUTH-08b). */
    public record Anonymized(int lines, Head before, Head after) {
    }

    public static final String RETENTION_ENV = "SAM_AUDIT_IP_RETENTION";

    /** {@code SAM_AUDIT_IP_RETENTION}, 90 días por defecto. */
    public static java.time.Duration retention(java.util.Map<String, String> config) {
        return dev.sam.common.auth.SessionClock.parse(RETENTION_ENV, config.getOrDefault(RETENTION_ENV, "90d"));
    }

    /**
     * RF-AUTH-08b (H-11): borra la IP de las líneas anteriores a {@code cutoff} y recalcula la cadena desde la primera
     * que cambia. Vacío si no había nada que borrar.
     */
    public synchronized java.util.Optional<Anonymized> anonymizeBefore(Instant cutoff) throws IOException {
        var out = new java.util.ArrayList<String>();
        var prev = ZEROS;
        var count = 0;
        var seq = 0L;
        for (var line : read(file)) {
            var json = JsonParser.parseString(line).getAsJsonObject();
            seq = json.get("seq").getAsLong();
            var ip = json.get("ip").getAsString();
            var old = !ip.isEmpty() && Instant.parse(json.get("t").getAsString()).isBefore(cutoff);
            if (old) {
                count++;
            }
            // Las líneas sin cambios se rearman idénticas; desde la primera que cambia, cambian los hashes
            var prefix = prefix(seq, json.get("t").getAsString(), json.get("type").getAsString(), json.get("actor").getAsString(),
                old ? "" : ip, json.get("detail").getAsString(), prev);
            prev = sha256(prefix);
            out.add(prefix + HASH_KEY + prev + "\"}");
        }
        if (count == 0) {
            return java.util.Optional.empty();
        }
        SecureFiles.writeString(file, String.join("\n", out) + "\n");
        var before = head;
        head = new Head(seq, prev);
        return java.util.Optional.of(new Anonymized(count, before, head));
    }

    private static String prefix(long seq, String t, String type, String actor, String ip, String detail, String prev) {
        return "{\"seq\":" + seq + ",\"t\":" + quote(t) + ",\"type\":" + quote(type) + ",\"actor\":" + quote(actor)
            + ",\"ip\":" + quote(ip) + ",\"detail\":" + quote(detail) + ",\"prev\":\"" + prev + "\"";
    }

    public synchronized Head head() {
        return head;
    }

    /** Recorre toda la cadena; un archivo que no existe es una cadena vacía y sana. */
    public static Verification verify(Path file) throws IOException {
        var prev = ZEROS;
        var lines = read(file);
        for (var i = 0; i < lines.size(); i++) {
            var at = i + 1;
            var entry = parse(lines.get(i));
            if (entry == null) {
                return Verification.broken(at, "línea mal formada");
            }
            if (!entry.hash().equals(sha256(entry.prefix()))) {
                return Verification.broken(at, "el hash no coincide");
            }
            if (entry.seq() != at || !entry.prev().equals(prev)) {
                return Verification.broken(at, "no sigue a la anterior");
            }
            prev = entry.hash();
        }
        return Verification.ok(lines.size());
    }

    /** Las últimas {@code n} líneas, tal cual. */
    public static List<String> last(Path file, int n) throws IOException {
        var lines = read(file);
        return List.copyOf(lines.subList(Math.max(0, lines.size() - Math.max(0, n)), lines.size()));
    }

    /** RF-AUTH-07e: las líneas de ese actor (sin importar mayúsculas), para exportar los datos de un jugador. */
    public static List<String> byActor(Path file, String actor) throws IOException {
        return read(file).stream().filter(line -> {
            try {
                return JsonParser.parseString(line).getAsJsonObject().get("actor").getAsString().equalsIgnoreCase(actor);
            } catch (RuntimeException e) {
                return false;
            }
        }).toList();
    }

    /** Copia solo del dueño al lado, con la fecha UTC en el nombre. */
    public static Path export(Path file, Instant now) throws IOException {
        var copy = file.resolveSibling(EXPORT_NAME.format(now));
        SecureFiles.write(copy, Files.readAllBytes(file));
        return copy;
    }

    private static List<String> read(Path file) throws IOException {
        try {
            return Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (NoSuchFileException e) {
            return List.of();
        }
    }

    /** {@code null} si no tiene la forma de una línea de la cadena. */
    private static Entry parse(String line) {
        // Lo demás (la llave que abre, las comillas y la llave que cierran) lo exige el parser de JSON
        var cut = line.length() - SUFFIX;
        if (!line.startsWith(HASH_KEY, cut)) {
            return null;
        }
        var hash = line.substring(cut + HASH_KEY.length(), line.length() - 2);
        var prefix = line.substring(0, cut);
        if (!HASH.matcher(hash).matches()) {
            return null;
        }
        try {
            JsonObject json = JsonParser.parseString(line).getAsJsonObject();
            return new Entry(json.get("seq").getAsLong(), json.get("prev").getAsString(), hash, prefix);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String quote(String text) {
        var out = new StringBuilder("\"");
        for (var c : text.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
