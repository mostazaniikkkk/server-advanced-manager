package dev.sam.common.lua;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Lo que se revisa de una imagen de un script antes de decodificarla (RF-LUA-08, RN-29): la firma PNG, que
 * el primer bloque sea un IHDR de 13 bytes, y los topes de 64 KiB y 256×256. La decodifica después
 * {@code NativeImage} de vanilla.
 */
public record PngInfo(int width, int height) {

    public static final int MAX_BYTES = 64 * 1024;
    public static final int MAX_SIDE = 256;
    private static final byte[] SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10};
    private static final byte[] IHDR = {0, 0, 0, 13, 'I', 'H', 'D', 'R'};
    private static final int HEADER = SIGNATURE.length + IHDR.length + 8;

    /** Con los topes de las imágenes de un script (64 KiB, 256×256). */
    public static PngInfo check(byte[] png) {
        return check(png, MAX_BYTES, MAX_SIDE);
    }

    /** @throws IllegalArgumentException con el motivo si no se puede usar */
    public static PngInfo check(byte[] png, int maxBytes, int maxSide) {
        if (png.length > maxBytes) {
            throw new IllegalArgumentException("la imagen supera los " + maxBytes / 1024 + " KiB");
        }
        if (png.length < HEADER || !Arrays.equals(png, 0, SIGNATURE.length, SIGNATURE, 0, SIGNATURE.length)
                || !Arrays.equals(png, SIGNATURE.length, SIGNATURE.length + IHDR.length, IHDR, 0, IHDR.length)) {
            throw new IllegalArgumentException("no es un PNG");
        }
        var size = ByteBuffer.wrap(png, SIGNATURE.length + IHDR.length, 8);
        var width = size.getInt();
        var height = size.getInt();
        if (width < 1 || height < 1) {
            throw new IllegalArgumentException("la imagen no tiene píxeles");
        }
        if (width > maxSide || height > maxSide) {
            throw new IllegalArgumentException("la imagen mide más de " + maxSide + "×" + maxSide);
        }
        return new PngInfo(width, height);
    }
}
