package dev.sam.common.auth;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import dev.sam.common.config.FilePermissions;

/**
 * Las cuentas en disco ({@code config/sam/accounts.json}). Si el archivo está dañado no se arranca con
 * cero cuentas, porque cualquiera podría volver a registrar el nick de otro: se rechaza y el login
 * queda cerrado (RF-CFG-04). Se escribe de forma atómica y solo para el dueño.
 */
public final class AccountsFile {

    public static final int VERSION = 1;

    private AccountsFile() {
    }

    public static String encode(List<Account> accounts) {
        var out = new StringWriter();
        try (var writer = new JsonWriter(out)) {
            writer.setIndent("  ");
            writer.beginObject();
            writer.name("version").value(VERSION);
            writer.name("accounts").beginArray();
            for (var account : accounts.stream().sorted(Comparator.comparing(Account::key)).toList()) {
                writer.beginObject();
                writer.name("nick").value(account.nick());
                writer.name("hash").value(account.passwordHash());
                writer.name("email").value(account.email());
                if (account.googleSub().isPresent()) {
                    writer.name("google").value(account.googleSub().get());
                }
                if (account.totp().isPresent()) {
                    writer.name("totp").value(account.totp().get());
                }
                writer.endObject();
            }
            writer.endArray();
            writer.endObject();
        } catch (IOException e) {
            throw new UncheckedIOException("No se puede fallar al escribir en memoria", e);
        }
        return out + "\n";
    }

    /** @throws IllegalArgumentException si el contenido no es válido */
    public static List<Account> decode(String json) {
        try {
            return read(json);
        } catch (IOException | IllegalStateException | NumberFormatException e) {
            throw invalid(e.getMessage());
        }
    }

    /** Sin archivo, no hay cuentas. */
    public static List<Account> load(Path file) throws IOException {
        if (!Files.exists(file)) {
            return List.of();
        }
        try {
            return decode(Files.readString(file));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage() + " (" + file + ")", e);
        }
    }

    /** Escribe en un temporal al lado y lo mueve encima: nunca queda un archivo a medias. */
    public static void save(Path file, List<Account> accounts) throws IOException {
        var dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        var temp = Files.createTempFile(dir, ".accounts", ".tmp");
        try {
            FilePermissions.restrictToOwner(temp);
            Files.writeString(temp, encode(accounts));
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static List<Account> read(String json) throws IOException {
        var reader = new JsonReader(new StringReader(json));
        Integer version = null;
        List<Account> accounts = null;
        var seen = new HashSet<String>();
        reader.beginObject();
        while (reader.hasNext()) {
            var name = reader.nextName();
            if (!seen.add(name)) {
                throw invalid("campo repetido " + name);
            }
            switch (name) {
                case "version" -> {
                    // nextInt acepta "1" entre comillas: la versión es un número
                    if (reader.peek() != JsonToken.NUMBER) {
                        throw invalid("version debe ser un número");
                    }
                    version = reader.nextInt();
                }
                case "accounts" -> accounts = readAccounts(reader);
                default -> throw invalid("campo desconocido " + name);
            }
        }
        reader.endObject();
        // En modo estricto, peek lanza si hay algo después del objeto
        reader.peek();
        if (version == null || version != VERSION || accounts == null) {
            throw invalid("falta la versión " + VERSION + " o la lista de cuentas");
        }
        return accounts;
    }

    private static List<Account> readAccounts(JsonReader reader) throws IOException {
        var accounts = new ArrayList<Account>();
        var keys = new HashSet<String>();
        var googleSubs = new HashSet<String>();
        reader.beginArray();
        while (reader.hasNext()) {
            var account = readAccount(reader);
            if (!keys.add(account.key())) {
                throw invalid("cuenta repetida " + account.key());
            }
            // RF-OAUTH-03: una cuenta de Google va a una sola cuenta del servidor
            if (account.googleSub().isPresent() && !googleSubs.add(account.googleSub().get())) {
                throw invalid("Google repetido en " + account.key());
            }
            accounts.add(account);
        }
        reader.endArray();
        return List.copyOf(accounts);
    }

    private static Account readAccount(JsonReader reader) throws IOException {
        var fields = new HashMap<String, String>();
        reader.beginObject();
        while (reader.hasNext()) {
            var name = reader.nextName();
            if (!List.of("nick", "hash", "email", "google", "totp").contains(name) || fields.containsKey(name)) {
                throw invalid("campo inválido " + name);
            }
            if (reader.peek() != JsonToken.STRING) {
                throw invalid(name + " debe ser texto");
            }
            fields.put(name, reader.nextString());
        }
        reader.endObject();
        var nick = fields.get("nick");
        var hash = fields.get("hash");
        var email = fields.get("email");
        var google = Optional.ofNullable(fields.get("google"));
        var totp = Optional.ofNullable(fields.get("totp"));
        if (fields.size() != 3 + (google.isPresent() ? 1 : 0) + (totp.isPresent() ? 1 : 0) || !Nick.isValid(nick) || !AccountService.isValidEmail(email)) {
            throw invalid("cuenta incompleta o con nick o correo inválido");
        }
        try {
            PasswordHash.parse(hash);
        } catch (IllegalArgumentException e) {
            throw invalid("hash inválido en la cuenta " + nick);
        }
        if (google.filter(String::isEmpty).isPresent()) {
            throw invalid("google vacío en la cuenta " + nick);
        }
        if (totp.filter(String::isEmpty).isPresent()) {
            throw invalid("totp vacío en la cuenta " + nick);
        }
        return new Account(Nick.normalize(nick), nick, hash, email, google, totp);
    }

    private static IllegalArgumentException invalid(String detail) {
        return new IllegalArgumentException("accounts.json inválido: " + detail);
    }
}
