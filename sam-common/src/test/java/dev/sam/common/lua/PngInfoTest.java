package dev.sam.common.lua;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

/**
 * Las imágenes de un script (RF-LUA-08, RN-29): antes de decodificarlas se revisan la firma PNG y la
 * cabecera IHDR, con tope de bytes y de dimensiones.
 */
class PngInfoTest {

    /** Un PNG mínimo: firma, IHDR y lo que sigue (no se decodifica). */
    static byte[] png(int width, int height, int extra) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10});
        out.writeBytes(ByteBuffer.allocate(8).putInt(13).put(new byte[] {'I', 'H', 'D', 'R'}).array());
        out.writeBytes(ByteBuffer.allocate(13).putInt(width).putInt(height).put((byte) 8).put((byte) 6).array());
        out.writeBytes(new byte[4 + extra]);
        return out.toByteArray();
    }

    @Test
    void unPngValidoDaSusDimensiones() {
        assertThat(PngInfo.check(png(16, 32, 0))).isEqualTo(new PngInfo(16, 32));
        assertThat(PngInfo.check(png(256, 256, 0))).isEqualTo(new PngInfo(256, 256));
        assertThat(PngInfo.check(png(1, 1, 64 * 1024 - 33))).isEqualTo(new PngInfo(1, 1));
        // Solo se leen la firma y el IHDR hasta las dimensiones (24 bytes)
        assertThat(PngInfo.check(java.util.Arrays.copyOf(png(5, 6, 0), 24))).isEqualTo(new PngInfo(5, 6));
        assertThatThrownBy(() -> PngInfo.check(java.util.Arrays.copyOf(png(5, 6, 0), 23))).hasMessage("no es un PNG");
    }

    @Test
    void loQueNoCumpleSeRechazaSinDecodificar() {
        rechazo(png(1, 1, 64 * 1024 - 32), "la imagen supera los 64 KiB");
        rechazo(new byte[] {(byte) 0x89, 'P', 'N', 'G'}, "no es un PNG");
        var firma = png(1, 1, 0);
        firma[1] = 'J';
        rechazo(firma, "no es un PNG");
        var cabecera = png(1, 1, 0);
        cabecera[12] = 'X';
        rechazo(cabecera, "no es un PNG");
        var largo = png(1, 1, 0);
        largo[11] = 14;
        rechazo(largo, "no es un PNG");
        rechazo(png(257, 1, 0), "la imagen mide más de 256×256");
        rechazo(png(1, 257, 0), "la imagen mide más de 256×256");
        rechazo(png(0, 1, 0), "la imagen no tiene píxeles");
        rechazo(png(1, 0, 0), "la imagen no tiene píxeles");
        rechazo(png(-1, 1, 0), "la imagen no tiene píxeles");
    }

    private static void rechazo(byte[] bytes, String motivo) {
        assertThatThrownBy(() -> PngInfo.check(bytes)).isInstanceOf(IllegalArgumentException.class).hasMessage(motivo);
    }
}
