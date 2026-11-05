package dev.sam.common.net;

import java.util.Optional;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import dev.sam.common.identity.ServerId;

/**
 * El campo {@code sam} de la respuesta de estado (PROTOCOLO.md 2.4): con él, un cliente SAM sabe que
 * debe conectar por TLS. Un cliente vanilla lo ignora. La ruta del WebSocket no se publica.
 */
public record StatusAdvert(ServerId serverId) {

    public static final String FIELD = "sam";
    public static final String VERSION = "1.0";

    private static final Gson GSON = new Gson();
    private static final Pattern PROTOCOL = Pattern.compile("\\d{1,3}\\.\\d{1,3}");
    private static final Pattern HEX_ID = Pattern.compile("[0-9a-f]{" + 2 * ServerId.LENGTH + "}");

    /** El JSON de estado con el campo {@code sam} agregado, si hay anuncio. */
    public static String render(JsonElement status, Optional<StatusAdvert> advert) {
        if (advert.isEmpty() || !status.isJsonObject()) {
            return GSON.toJson(status);
        }
        var sam = new JsonObject();
        sam.addProperty("v", VERSION);
        sam.addProperty("id", advert.get().serverId().hex());
        sam.addProperty("tls", true);
        var copy = status.getAsJsonObject().deepCopy();
        copy.add(FIELD, sam);
        return GSON.toJson(copy);
    }

    /** El anuncio de un estado recibido; vacío si no trae {@code sam} o no es válido. */
    public static Optional<StatusAdvert> read(JsonElement status) {
        if (!status.isJsonObject() || !(status.getAsJsonObject().get(FIELD) instanceof JsonObject sam)) {
            return Optional.empty();
        }
        var valid = text(sam, "v", PROTOCOL) && text(sam, "id", HEX_ID)
            && sam.get("tls") instanceof JsonPrimitive tls && tls.isBoolean() && tls.getAsBoolean();
        return valid ? Optional.of(new StatusAdvert(ServerId.fromHex(sam.get("id").getAsString()))) : Optional.empty();
    }

    private static boolean text(JsonObject object, String key, Pattern format) {
        return object.get(key) instanceof JsonPrimitive value && value.isString() && format.matcher(value.getAsString()).matches();
    }
}
