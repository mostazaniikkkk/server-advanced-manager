package dev.sam.common.identity;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import dev.sam.common.net.ServerAddress;

/**
 * Persistencia del almacén de pins en {@code config/sam-client/pins.json} (PROTOCOLO.md 3.3).
 *
 * <p><b>Un archivo dañado o manipulado nunca debilita la protección</b>: lo que no se puede
 * validar se descarta (ese servidor vuelve a la primera conexión) y se informa en
 * {@link LoadResult#problems()} para que la interfaz avise al jugador.
 *
 * <ul>
 *   <li>JSON ilegible, de otra versión o con claves de primer nivel duplicadas → almacén vacío.</li>
 *   <li>Servidor con un pin que no coincide con su clave, campos inválidos, faltantes o
 *       duplicados, o server_id repetido → se descarta (con sus direcciones).</li>
 *   <li>Dirección no canónica, ilegible, repetida o hacia un servidor no fijado → se descarta.</li>
 *   <li>Campos desconocidos → se ignoran (compatibilidad futura).</li>
 * </ul>
 *
 * <p>Se lee con el {@link JsonReader} de Gson en modo estricto y por streaming: el árbol de Gson
 * ({@code JsonParser}) activa el modo permisivo y se queda con la última clave duplicada.
 */
public final class PinStoreJson {

    public static final int VERSION = 1;

    /** @param problems motivos de lo descartado, en lenguaje para mostrar al jugador */
    public record LoadResult(PinStore store, List<String> problems) {
        public LoadResult {
            problems = List.copyOf(problems);
        }
    }

    private static final class FormatException extends Exception {
        private static final long serialVersionUID = 1L;

        FormatException(String message) {
            super(message);
        }
    }

    /** Valor de un campo tal como vino: un string, o null si era de otro tipo. */
    private record Field(String value) {
    }

    /** Entrada de servidor: sus campos string, o el motivo por el que no se pudo leer. */
    private record RawServer(Map<String, String> fields, String error) {
    }

    private PinStoreJson() {
    }

    // ===== Escritura =====

    /** Escritura determinista: servidores por server_id y direcciones por forma canónica. */
    public static String encode(PinStore store) {
        var out = new StringWriter();
        try (var writer = new JsonWriter(out)) {
            writer.setIndent("  ");
            writer.beginObject();
            writer.name("version").value(VERSION);
            writer.name("servers").beginObject();
            for (var server : store.servers().values().stream()
                    .sorted(Comparator.comparing(s -> s.id().hex())).toList()) {
                writer.name(server.id().hex()).beginObject();
                writer.name("pin").value(server.pin().hex());
                writer.name("spki").value(Base64.getEncoder().encodeToString(server.key().spki()));
                writer.name("first_seen").value(server.firstSeen().toString());
                writer.name("name").value(server.name());
                writer.endObject();
            }
            writer.endObject();
            writer.name("addresses").beginObject();
            for (var entry : store.addresses().entrySet().stream()
                    .sorted(Comparator.comparing(e -> e.getKey().canonical())).toList()) {
                writer.name(entry.getKey().canonical()).value(entry.getValue().hex());
            }
            writer.endObject();
            writer.endObject();
        } catch (IOException e) {
            throw new UncheckedIOException("No se puede fallar al escribir en memoria", e);
        }
        return out + "\n";
    }

    // ===== Lectura =====

    public static LoadResult decode(String json) {
        var servers = new LinkedHashMap<String, List<RawServer>>();
        var addresses = new LinkedHashMap<String, List<Field>>();
        try {
            readFile(json, servers, addresses);
        } catch (IOException | IllegalStateException | NumberFormatException | FormatException e) {
            return new LoadResult(PinStore.empty(), List.of("pins.json ilegible: " + e.getMessage()));
        }
        var problems = new ArrayList<String>();
        var store = PinStore.empty();
        for (var entry : servers.entrySet()) {
            try {
                store = store.withServer(buildServer(entry.getKey(), entry.getValue()));
            } catch (FormatException e) {
                problems.add("Servidor " + entry.getKey() + " descartado: " + e.getMessage());
            }
        }
        for (var entry : addresses.entrySet()) {
            try {
                var address = buildAddress(entry.getKey(), entry.getValue(), store);
                store = store.addAddress(address, ServerId.fromHex(entry.getValue().get(0).value()));
            } catch (FormatException e) {
                problems.add("Dirección " + entry.getKey() + " descartada: " + e.getMessage());
            }
        }
        return new LoadResult(store, problems);
    }

    private static void readFile(String json, Map<String, List<RawServer>> servers, Map<String, List<Field>> addresses)
            throws IOException, FormatException {
        // JsonReader es estricto por defecto: beginObject() lanza si el documento no es un objeto
        var reader = new JsonReader(new StringReader(json));
        var seen = new HashMap<String, Boolean>();
        reader.beginObject();
        while (reader.hasNext()) {
            var name = reader.nextName();
            if (seen.put(name, true) != null) {
                throw new FormatException("clave \"" + name + "\" duplicada");
            }
            switch (name) {
                case "version" -> {
                    if (reader.peek() != JsonToken.NUMBER || reader.nextInt() != VERSION) {
                        throw new FormatException("versión no soportada (se esperaba " + VERSION + ")");
                    }
                }
                case "servers" -> readServers(reader, servers);
                case "addresses" -> readAddresses(reader, addresses);
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        // En modo estricto, peek() lanza MalformedJsonException si hay contenido tras el objeto
        reader.peek();
        for (var required : List.of("version", "servers", "addresses")) {
            if (!seen.containsKey(required)) {
                throw new FormatException("falta \"" + required + "\"");
            }
        }
    }

    private static void readServers(JsonReader reader, Map<String, List<RawServer>> servers) throws IOException {
        reader.beginObject();
        while (reader.hasNext()) {
            var id = reader.nextName();
            servers.computeIfAbsent(id, k -> new ArrayList<>()).add(readServer(reader));
        }
        reader.endObject();
    }

    private static RawServer readServer(JsonReader reader) throws IOException {
        if (reader.peek() != JsonToken.BEGIN_OBJECT) {
            reader.skipValue();
            return new RawServer(Map.of(), "la entrada no es un objeto");
        }
        var fields = new HashMap<String, String>();
        String error = null;
        reader.beginObject();
        while (reader.hasNext()) {
            var name = reader.nextName();
            var value = readString(reader);
            if (fields.containsKey(name)) {
                error = "campo \"" + name + "\" duplicado";
            }
            fields.put(name, value.value());
        }
        reader.endObject();
        return new RawServer(fields, error);
    }

    private static void readAddresses(JsonReader reader, Map<String, List<Field>> addresses) throws IOException {
        reader.beginObject();
        while (reader.hasNext()) {
            var address = reader.nextName();
            addresses.computeIfAbsent(address, k -> new ArrayList<>()).add(readString(reader));
        }
        reader.endObject();
    }

    private static Field readString(JsonReader reader) throws IOException {
        if (reader.peek() == JsonToken.STRING) {
            return new Field(reader.nextString());
        }
        reader.skipValue();
        return new Field(null);
    }

    private static PinnedServer buildServer(String rawId, List<RawServer> entries) throws FormatException {
        if (entries.size() > 1) {
            throw new FormatException("server_id duplicado (ambiguo)");
        }
        var entry = entries.get(0);
        if (entry.error() != null) {
            throw new FormatException(entry.error());
        }
        try {
            var id = ServerId.fromHex(rawId);
            var key = ServerPublicKey.fromSpki(Base64.getDecoder().decode(required(entry, "spki")));
            if (!key.pin().equals(Pin.fromHex(required(entry, "pin")))) {
                throw new FormatException("el pin no coincide con la clave (posible manipulación)");
            }
            return new PinnedServer(id, key, required(entry, "name"), Instant.parse(required(entry, "first_seen")));
        } catch (IllegalArgumentException | DateTimeParseException e) {
            throw new FormatException(e.getMessage());
        }
    }

    private static String required(RawServer entry, String field) throws FormatException {
        var value = entry.fields().get(field);
        if (value == null) {
            throw new FormatException("falta el campo \"" + field + "\" o no es un string");
        }
        return value;
    }

    private static ServerAddress buildAddress(String rawAddress, List<Field> values, PinStore store) throws FormatException {
        if (values.size() > 1) {
            throw new FormatException("dirección duplicada (ambigua)");
        }
        var target = values.get(0).value();
        if (target == null) {
            throw new FormatException("el servidor asociado no es un string");
        }
        ServerAddress address;
        ServerId id;
        try {
            address = ServerAddress.parse(rawAddress);
            id = ServerId.fromHex(target);
        } catch (IllegalArgumentException e) {
            throw new FormatException(e.getMessage());
        }
        if (!address.canonical().equals(rawAddress)) {
            throw new FormatException("no está en forma canónica (" + address.canonical() + ")");
        }
        if (store.server(id).isEmpty()) {
            throw new FormatException("apunta al servidor " + target + ", que no está fijado");
        }
        return address;
    }
}
