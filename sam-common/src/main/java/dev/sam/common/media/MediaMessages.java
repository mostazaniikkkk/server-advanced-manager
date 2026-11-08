package dev.sam.common.media;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;

/**
 * Los mensajes de imágenes de la fase play (docs/plugins/sam-mensajes.md): {@code sam:media_up},
 * {@code media_ready}, {@code media_get}, {@code media_down} y {@code media_failed}. Una imagen viaja en
 * fragmentos de 32 KiB, en orden, y mide como mucho 256 KiB (8 fragmentos).
 */
public final class MediaMessages {

    public static final int CHUNK = 32 * 1024;
    private static final int MAX_CHUNKS = MediaStore.MAX_BYTES / CHUNK;
    private static final int ID = 16;
    private static final int MAX_REASON = 128;

    private MediaMessages() {
    }

    private static byte[] id(byte[] media) {
        if (media.length != ID) {
            throw new IllegalArgumentException("el id de una imagen mide 16 bytes");
        }
        return media.clone();
    }

    /** {@code sam:media_up}, cliente → servidor: un fragmento de una subida (su número lo elige el cliente). */
    public record Up(int upload, int index, int total, byte[] data) {
        public static final String ID_NAME = "media_up";
        public static final int MAX_BYTES = CHUNK + 32;

        public Up {
            data = data.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }

        public void write(SamWriter out) {
            out.varInt(upload).varInt(index).varInt(total).bytes(data, CHUNK);
        }

        public static Up read(SamReader in) {
            return new Up(in.varInt(), in.varInt(), in.varInt(), in.bytes(CHUNK));
        }
    }

    /** {@code sam:media_ready}, servidor → cliente: la subida quedó guardada con este id. */
    public record Ready(int upload, byte[] media) {
        public static final String ID_NAME = "media_ready";

        public Ready {
            media = id(media);
        }

        @Override
        public byte[] media() {
            return media.clone();
        }

        public void write(SamWriter out) {
            out.varInt(upload).fixed(media, ID);
        }

        public static Ready read(SamReader in) {
            var upload = in.varInt();
            var media = in.fixed(ID);
            return new Ready(upload, media);
        }
    }

    /** {@code sam:media_get}, cliente → servidor: pide una imagen. */
    public record Get(byte[] media) {
        public static final String ID_NAME = "media_get";
        public static final int MAX_BYTES = ID;

        public Get {
            media = id(media);
        }

        @Override
        public byte[] media() {
            return media.clone();
        }

        public void write(SamWriter out) {
            out.fixed(media, ID);
        }

        public static Get read(SamReader in) {
            return new Get(in.fixed(ID));
        }
    }

    /** {@code sam:media_down}, servidor → cliente: un fragmento de una imagen pedida. */
    public record Down(byte[] media, int index, int total, byte[] data) {
        public static final String ID_NAME = "media_down";
        public static final int MAX_BYTES = CHUNK + 48;

        public Down {
            media = id(media);
            data = data.clone();
        }

        @Override
        public byte[] media() {
            return media.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }

        public void write(SamWriter out) {
            out.fixed(media, ID).varInt(index).varInt(total).bytes(data, CHUNK);
        }

        public static Down read(SamReader in) {
            var media = in.fixed(ID);
            return new Down(media, in.varInt(), in.varInt(), in.bytes(CHUNK));
        }
    }

    /**
     * {@code sam:media_failed}, servidor → cliente: una subida (su número como VarInt) o una descarga (el id) que
     * no se pudo. Para una descarga el motivo es siempre el mismo, exista o no la imagen.
     */
    public record Failed(byte[] ref, String reason) {
        public static final String ID_NAME = "media_failed";

        public Failed {
            ref = ref.clone();
        }

        @Override
        public byte[] ref() {
            return ref.clone();
        }

        public void write(SamWriter out) {
            out.bytes(ref, ID).string(reason, MAX_REASON);
        }

        public static Failed read(SamReader in) {
            return new Failed(in.bytes(ID), in.string(MAX_REASON));
        }
    }

    /** Los fragmentos de una imagen; una vacía es un fragmento vacío. */
    public static List<byte[]> chunks(byte[] data) {
        var chunks = new ArrayList<byte[]>();
        var offset = 0;
        do {
            chunks.add(Arrays.copyOfRange(data, offset, Math.min(data.length, offset + CHUNK)));
            offset += CHUNK;
        } while (offset < data.length);
        return chunks;
    }

    /** Arma una imagen fragmento a fragmento, en orden y sin pasarse de 256 KiB; al completarla vuelve a empezar. */
    public static final class Assembly {

        private int next;
        private int total;
        private ByteArrayOutputStream data = new ByteArrayOutputStream();

        /** @throws ProtocolException (SAM-P002) si el fragmento no corresponde */
        public Optional<byte[]> accept(int index, int total, byte[] chunk) {
            // El primero fija el total (≥ 1); los demás deben seguir en orden con el mismo total
            if (index != next || total < 1 || next > 0 && total != this.total) {
                throw outOfState("fragmento fuera de orden");
            }
            if (total > MAX_CHUNKS) {
                throw outOfState("una imagen tiene como mucho " + MAX_CHUNKS + " fragmentos");
            }
            if (data.size() + chunk.length > MediaStore.MAX_BYTES) {
                throw outOfState("la imagen supera los 256 KiB");
            }
            this.total = total;
            data.writeBytes(chunk);
            next++;
            if (next < total) {
                return Optional.empty();
            }
            var complete = data.toByteArray();
            next = 0;
            data = new ByteArrayOutputStream();
            return Optional.of(complete);
        }

        private static ProtocolException outOfState(String message) {
            return new ProtocolException(ProtocolException.OUT_OF_STATE, message);
        }
    }
}
