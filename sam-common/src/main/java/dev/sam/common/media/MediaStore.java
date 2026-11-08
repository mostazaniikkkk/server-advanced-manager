package dev.sam.common.media;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.sam.common.lua.PngInfo;

/**
 * Las imágenes que suben los jugadores (capacidad {@code media}, docs/plugins/sam-mensajes.md): solo en
 * memoria, PNG de hasta 512×512 y 256 KiB, 5 por minuto por jugador, una hora de vida y 64 MiB en total
 * (las más viejas salen primero). Solo las descarga el dueño o a quien él se las compartió. No es seguro
 * entre hilos: se usa en el del servidor.
 */
public final class MediaStore {

    public static final int MAX_BYTES = 256 * 1024;
    public static final int MAX_SIDE = 512;
    public static final long CAPACITY = 64L * 1024 * 1024;
    private static final int PER_MINUTE = 5;
    private static final long TTL_SECONDS = 3600;

    private record Item(String owner, byte[] png, long created, Set<String> shared) {
    }

    private final SecureRandom random;
    private final long capacity;
    /** Por id en hex, en orden de llegada (la primera es la más vieja). */
    private final Map<String, Item> items = new LinkedHashMap<>();
    private final Map<String, ArrayDeque<Long>> recent = new HashMap<>();
    private long used;

    public MediaStore(SecureRandom random, long capacity) {
        this.random = random;
        this.capacity = capacity;
    }

    /**
     * @return el id (16 bytes aleatorios)
     * @throws IllegalArgumentException si no es un PNG dentro de los topes o el jugador se pasó del ritmo
     */
    public byte[] put(String owner, byte[] png, long now) {
        expire(now);
        var who = key(owner);
        var times = recent.computeIfAbsent(who, k -> new ArrayDeque<>());
        while (!times.isEmpty() && times.peekFirst() <= now - 60) {
            times.pollFirst();
        }
        if (times.size() >= PER_MINUTE) {
            throw new IllegalArgumentException("como mucho " + PER_MINUTE + " imágenes por minuto");
        }
        PngInfo.check(png, MAX_BYTES, MAX_SIDE);
        while (used + png.length > capacity) {
            var oldest = items.keySet().iterator().next();
            used -= items.remove(oldest).png().length;
        }
        var id = new byte[16];
        random.nextBytes(id);
        items.put(HexFormat.of().formatHex(id), new Item(who, png.clone(), now, new HashSet<>()));
        used += png.length;
        times.addLast(now);
        return id;
    }

    /** Deja que {@code to} descargue la imagen; solo si {@code from} es el dueño. */
    public boolean share(byte[] id, String from, String to, long now) {
        expire(now);
        var item = items.get(HexFormat.of().formatHex(id));
        if (item == null || !item.owner().equals(key(from))) {
            return false;
        }
        item.shared().add(key(to));
        return true;
    }

    /** La imagen, si existe y {@code requester} es el dueño o se la compartieron (el mismo vacío en ambos casos). */
    public Optional<byte[]> get(byte[] id, String requester, long now) {
        expire(now);
        var item = items.get(HexFormat.of().formatHex(id));
        var who = key(requester);
        if (item == null || !item.owner().equals(who) && !item.shared().contains(who)) {
            return Optional.empty();
        }
        return Optional.of(item.png().clone());
    }

    /** Los bytes de imágenes que hay en memoria. */
    public long used() {
        return used;
    }

    private void expire(long now) {
        var it = items.values().iterator();
        while (it.hasNext()) {
            var item = it.next();
            if (now - item.created() < TTL_SECONDS) {
                break;
            }
            used -= item.png().length;
            it.remove();
        }
    }

    private static String key(String nick) {
        return nick.toLowerCase(Locale.ROOT);
    }
}
