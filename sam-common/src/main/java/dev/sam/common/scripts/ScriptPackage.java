package dev.sam.common.scripts;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * El paquete de un script en tránsito (PROTOCOLO.md 5.5): la lista de sus archivos ordenada por ruta, así
 * cada script tiene una sola codificación y un solo {@code sha256}. Se envía en fragmentos de 128 KiB que
 * {@link Assembler} reconstruye con los límites de la conexión.
 */
public final class ScriptPackage {

    public static final int CHUNK = 128 * 1024;
    public static final int MAX_PACKAGE = 4 * 1024 * 1024;
    public static final int MAX_TOTAL = 16 * 1024 * 1024;
    private static final int MAX_FILES = 257;
    private static final int MAX_FILE = 512 * 1024;

    private ScriptPackage() {
    }

    /** @throws IllegalArgumentException con una ruta inválida, demasiados archivos o más de 4 MiB */
    public static byte[] encode(Map<String, byte[]> files) {
        var sorted = new TreeMap<ScriptPath, byte[]>();
        files.forEach((path, data) -> sorted.put(ScriptPath.of(path), data));
        var buf = Unpooled.buffer();
        new SamWriter(buf).list(List.copyOf(sorted.entrySet()), MAX_FILES,
            (w, file) -> w.string(file.getKey().value(), ScriptPath.MAX_LENGTH).bytes(file.getValue(), MAX_FILE));
        if (buf.readableBytes() > MAX_PACKAGE) {
            throw new IllegalArgumentException("el script supera los 4 MiB");
        }
        return ByteBufUtil.getBytes(buf);
    }

    /** Los archivos, en orden; solo la codificación canónica se acepta. */
    public static Map<String, byte[]> decode(byte[] bytes) {
        var entries = SamReader.decode(Unpooled.wrappedBuffer(bytes), MAX_PACKAGE, in -> in.list(MAX_FILES, ScriptPackage::file));
        var files = new TreeMap<String, byte[]>();
        for (var entry : entries) {
            if (!files.isEmpty() && files.lastKey().compareTo(entry.getKey()) >= 0) {
                throw new ProtocolException(ProtocolException.MALFORMED, "paquete con rutas desordenadas o repetidas");
            }
            files.put(entry.getKey(), entry.getValue());
        }
        return files;
    }

    private static Map.Entry<String, byte[]> file(SamReader in) {
        var path = in.string(ScriptPath.MAX_LENGTH);
        var data = in.bytes(MAX_FILE);
        return ProtocolException.fromRead(() -> Map.entry(ScriptPath.of(path).value(), data));
    }

    public static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("toda JVM trae SHA-256", e);
        }
    }

    /** Fragmentos de 128 KiB; un paquete vacío es un fragmento vacío. */
    public static List<byte[]> chunks(byte[] bytes) {
        var chunks = new ArrayList<byte[]>();
        var offset = 0;
        do {
            chunks.add(Arrays.copyOfRange(bytes, offset, Math.min(bytes.length, offset + CHUNK)));
            offset += CHUNK;
        } while (offset < bytes.length);
        return chunks;
    }

    /**
     * Reconstruye los scripts pedidos: cada uno llega en orden, solo los ofrecidos, sin pasarse del tamaño
     * anunciado, y al completarse su contenido debe dar su hash. Si no, {@code SAM-P002}.
     */
    public static final class Assembler {

        private final Map<String, Integer> sizes;
        private final Map<String, Progress> progress = new HashMap<>();

        private static final class Progress {
            private final int total;
            private int next;
            private final ByteArrayOutputStream data = new ByteArrayOutputStream();

            private Progress(int total) {
                this.total = total;
            }
        }

        /** @param sizes tamaño de cada script pedido, por su hash en hex */
        public Assembler(Map<String, Integer> sizes) {
            if (sizes.values().stream().mapToLong(Integer::longValue).sum() > MAX_TOTAL) {
                throw new IllegalArgumentException("la descarga supera los 16 MiB");
            }
            this.sizes = new HashMap<>(sizes);
        }

        /** El paquete completo al llegar su último fragmento. */
        public Optional<byte[]> accept(byte[] sha256, int index, int total, byte[] data) {
            var hex = HexFormat.of().formatHex(sha256);
            var size = sizes.get(hex);
            if (size == null) {
                throw outOfState("fragmento de un script no ofrecido");
            }
            var current = progress.computeIfAbsent(hex, h -> new Progress(total));
            if (index != current.next || total != current.total || index >= total) {
                throw outOfState("fragmento fuera de orden");
            }
            if (current.data.size() + data.length > size) {
                throw outOfState("el script supera su tamaño");
            }
            current.data.writeBytes(data);
            current.next++;
            if (current.next < total) {
                return Optional.empty();
            }
            var bytes = current.data.toByteArray();
            if (!MessageDigest.isEqual(sha256(bytes), sha256)) {
                throw outOfState("el script no coincide con su hash");
            }
            sizes.remove(hex);
            progress.remove(hex);
            return Optional.of(bytes);
        }

        /** Todos los scripts pedidos llegaron. */
        public boolean done() {
            return sizes.isEmpty();
        }

        private static ProtocolException outOfState(String message) {
            return new ProtocolException(ProtocolException.OUT_OF_STATE, message);
        }
    }
}
