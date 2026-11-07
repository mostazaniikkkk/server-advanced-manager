package dev.sam.common.lua;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Pattern;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * Los datos guardados de un script ({@code storage}, RS-LUA-02b, PROTOCOLO.md 8.3): clave → {@code LuaData},
 * con cuota de 1024 claves y 256 KiB (claves más valores). El archivo que guarda SAM es la lista ordenada de
 * pares con el codec de 4.1; se lee con las mismas reglas.
 */
public final class ScriptStore {

    public static final int MAX_KEYS = 1024;
    public static final int MAX_BYTES = 256 * 1024;
    private static final int MAX_KEY = 64;
    private static final Pattern KEY = Pattern.compile("[a-z0-9_.:-]{1,64}");

    private final TreeMap<String, byte[]> values = new TreeMap<>();
    private int used;
    private boolean dirty;

    public Optional<byte[]> get(String key) {
        return Optional.ofNullable(values.get(key)).map(byte[]::clone);
    }

    /**
     * Guarda o, con un valor vacío, borra.
     *
     * @throws IllegalArgumentException si la clave no es válida o se pasa de la cuota (y no cambia nada)
     */
    public void set(String key, Optional<byte[]> value) {
        if (!KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("clave inválida \"" + key + "\": [a-z0-9_.:-], hasta 64");
        }
        var previous = values.get(key);
        var before = previous == null ? 0 : size(key, previous);
        if (value.isEmpty()) {
            if (values.remove(key) != null) {
                used -= before;
                dirty = true;
            }
            return;
        }
        var bytes = value.get();
        if (bytes.length > LuaData.MAX_BYTES) {
            throw new IllegalArgumentException("el valor supera los " + LuaData.MAX_BYTES + " bytes");
        }
        if (previous == null && values.size() >= MAX_KEYS) {
            throw new IllegalArgumentException("como mucho " + MAX_KEYS + " claves por script");
        }
        var after = used - before + size(key, bytes);
        if (after > MAX_BYTES) {
            throw new IllegalArgumentException("el script supera los 256 KiB de datos guardados");
        }
        values.put(key, bytes.clone());
        used = after;
        dirty = true;
    }

    private static int size(String key, byte[] value) {
        return key.getBytes(StandardCharsets.UTF_8).length + value.length;
    }

    public List<String> keys() {
        return List.copyOf(values.keySet());
    }

    /** Los bytes de la cuota que se están usando. */
    public int used() {
        return used;
    }

    /** Si cambió desde la última vez que se guardó. */
    public boolean dirty() {
        return dirty;
    }

    public void saved() {
        dirty = false;
    }

    public byte[] encode() {
        var buf = Unpooled.buffer();
        new SamWriter(buf).list(List.copyOf(values.entrySet()), MAX_KEYS,
            (w, entry) -> w.string(entry.getKey(), MAX_KEY).bytes(entry.getValue(), LuaData.MAX_BYTES));
        return ByteBufUtil.getBytes(buf);
    }

    /** @throws ProtocolException si el archivo no cumple el formato o las reglas */
    public static ScriptStore decode(byte[] bytes) {
        var entries = SamReader.decode(Unpooled.wrappedBuffer(bytes), Integer.MAX_VALUE,
            in -> in.list(MAX_KEYS, r -> Map.entry(r.string(MAX_KEY), r.bytes(LuaData.MAX_BYTES))));
        var store = new ScriptStore();
        String last = null;
        for (var entry : entries) {
            if (last != null && last.compareTo(entry.getKey()) >= 0) {
                throw new ProtocolException(ProtocolException.MALFORMED, "claves desordenadas o repetidas");
            }
            last = entry.getKey();
            ProtocolException.fromRead(() -> {
                store.set(entry.getKey(), Optional.of(entry.getValue()));
                return null;
            });
        }
        store.saved();
        return store;
    }
}
