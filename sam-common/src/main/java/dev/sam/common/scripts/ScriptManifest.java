package dev.sam.common.scripts;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

/**
 * El {@code manifest.json} de un script (RF-LUA-01, PROTOCOLO.md 8.3). Lectura estricta: campos
 * desconocidos, repetidos o de otro tipo se rechazan. El id debe ser el nombre de la carpeta.
 */
public record ScriptManifest(String id, String version, Side side, List<String> dependencies, List<String> capabilities,
        boolean required) {

    public static final int MAX_BYTES = 4096;
    private static final int MAX_DEPENDENCIES = 16;
    private static final int MAX_CAPABILITIES = 32;
    private static final Pattern ID = Pattern.compile("[a-z0-9_]{1,32}");
    private static final Pattern VERSION = Pattern.compile("[\\x20-\\x7E]{1,32}");
    private static final Pattern CAPABILITY = Pattern.compile("[a-z0-9_:.]{1,48}");
    private static final List<String> FIELDS = List.of("id", "version", "side", "dependencies", "capabilities", "required");

    /** Dónde corre el script. */
    public enum Side {
        SERVER, CLIENT, BOTH
    }

    public ScriptManifest {
        dependencies = List.copyOf(dependencies);
        capabilities = List.copyOf(capabilities);
    }

    /** @param folder el nombre de la carpeta del script dentro de {@code sam_scripts/} */
    public static ScriptManifest parse(String folder, byte[] json) {
        if (json.length > MAX_BYTES) {
            throw invalid("supera los " + MAX_BYTES + " bytes");
        }
        Map<String, Object> fields;
        try {
            fields = read(new String(json, StandardCharsets.UTF_8));
        } catch (IOException | IllegalStateException e) {
            throw invalid("no es un objeto JSON válido");
        }
        if (!(fields.get("id") instanceof String id) || !(fields.get("version") instanceof String version)
                || !(fields.get("side") instanceof String side)) {
            throw invalid("faltan id, version o side");
        }
        if (!id.equals(folder)) {
            throw invalid("el id \"" + id + "\" no coincide con la carpeta \"" + folder + "\"");
        }
        if (!VERSION.matcher(version).matches()) {
            throw invalid("version debe tener 1 a 32 caracteres imprimibles");
        }
        var parsedSide = switch (side) {
            case "server" -> Side.SERVER;
            case "client" -> Side.CLIENT;
            case "both" -> Side.BOTH;
            default -> throw invalid("side debe ser server, client o both");
        };
        var dependencies = list(fields, "dependencies", MAX_DEPENDENCIES, ID, "dependencia", "dependencias");
        if (dependencies.contains(id)) {
            throw invalid("un script no puede depender de sí mismo");
        }
        var capabilities = list(fields, "capabilities", MAX_CAPABILITIES, CAPABILITY, "capacidad", "capacidades");
        var required = (Boolean) fields.getOrDefault("required", Boolean.FALSE);
        return new ScriptManifest(id, version, parsedSide, dependencies, capabilities, required);
    }

    public boolean has(String capability) {
        return capabilities.contains(capability);
    }

    public boolean runsOnServer() {
        return side != Side.CLIENT;
    }

    public boolean runsOnClient() {
        return side != Side.SERVER;
    }

    private static Map<String, Object> read(String json) throws IOException {
        var reader = new JsonReader(new StringReader(json));
        var fields = new HashMap<String, Object>();
        reader.beginObject();
        while (reader.hasNext()) {
            var name = reader.nextName();
            if (!FIELDS.contains(name)) {
                throw invalid("campo desconocido \"" + name + "\"");
            }
            if (fields.containsKey(name)) {
                throw invalid("campo repetido \"" + name + "\"");
            }
            fields.put(name, value(reader, name));
        }
        reader.endObject();
        // En modo estricto, peek lanza si hay algo después del objeto
        reader.peek();
        return fields;
    }

    private static Object value(JsonReader reader, String name) throws IOException {
        switch (name) {
            case "required" -> {
                if (reader.peek() != JsonToken.BOOLEAN) {
                    throw invalid("required debe ser true o false");
                }
                return reader.nextBoolean();
            }
            case "dependencies", "capabilities" -> {
                if (reader.peek() != JsonToken.BEGIN_ARRAY) {
                    throw invalid(name + " debe ser una lista de textos");
                }
                var values = new ArrayList<String>();
                reader.beginArray();
                while (reader.hasNext()) {
                    if (reader.peek() != JsonToken.STRING) {
                        throw invalid(name + " debe ser una lista de textos");
                    }
                    values.add(reader.nextString());
                }
                reader.endArray();
                return values;
            }
            default -> {
                if (reader.peek() != JsonToken.STRING) {
                    throw invalid(name + " debe ser texto");
                }
                return reader.nextString();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> list(Map<String, Object> fields, String name, int max, Pattern rule, String one, String many) {
        var values = (List<String>) fields.getOrDefault(name, List.of());
        if (values.size() > max) {
            throw invalid("como mucho " + max + " " + many);
        }
        var seen = new HashSet<String>();
        for (var value : values) {
            if (!rule.matcher(value).matches()) {
                throw invalid(one + " inválida \"" + value + "\"");
            }
            if (!seen.add(value)) {
                throw invalid(one + " repetida \"" + value + "\"");
            }
        }
        return values;
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException("manifest.json inválido: " + reason);
    }
}
