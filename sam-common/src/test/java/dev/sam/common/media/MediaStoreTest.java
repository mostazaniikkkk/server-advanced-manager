package dev.sam.common.media;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import dev.sam.common.lua.PngInfoTest;

/**
 * Las imágenes que suben los jugadores (capacidad {@code media}, docs/plugins/sam-mensajes.md): viven solo en
 * memoria, con dueño, se descargan solo si se compartieron, y tienen topes de tamaño, ritmo, tiempo y total.
 */
class MediaStoreTest {

    private static final byte[] FOTO = PngInfoTest.png(512, 512, 100);

    @Test
    void soloElDuenoYAQuienSeLaCompartioLaDescargan() {
        var store = new MediaStore(new SecureRandom(), MediaStore.CAPACITY);
        var id = store.put("Steve", FOTO, 1000);
        assertThat(id).hasSize(16);
        assertThat(store.get(id, "steve", 1000)).hasValueSatisfying(png -> assertThat(png).isEqualTo(FOTO));
        assertThat(store.get(id, "Alex", 1000)).isEmpty();
        assertThat(store.share(id, "Alex", "Notch", 1000)).as("solo el dueño comparte").isFalse();
        assertThat(store.share(id, "STEVE", "Alex", 1000)).isTrue();
        assertThat(store.get(id, "alex", 1000)).isPresent();
        assertThat(store.get(id, "notch", 1000)).isEmpty();
        assertThat(store.share(new byte[16], "steve", "alex", 1000)).isFalse();
        assertThat(store.get(new byte[16], "steve", 1000)).isEmpty();
        // Lo devuelto es una copia
        store.get(id, "steve", 1000).orElseThrow()[0] = 0;
        assertThat(store.get(id, "steve", 1000).orElseThrow()[0]).isEqualTo((byte) 0x89);
        assertThat(store.used()).isEqualTo(FOTO.length);
    }

    @Test
    void cincoPorMinutoPorJugador() {
        var store = new MediaStore(new SecureRandom(), MediaStore.CAPACITY);
        for (var i = 0; i < 5; i++) {
            store.put("steve", FOTO, 100 + i);
        }
        assertThatThrownBy(() -> store.put("STEVE", FOTO, 159)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("como mucho 5 imágenes por minuto");
        store.put("alex", FOTO, 159);
        // A los 60 s de la primera, hay lugar para una más
        store.put("steve", FOTO, 160);
        assertThatThrownBy(() -> store.put("steve", FOTO, 160)).isInstanceOf(IllegalArgumentException.class);
        // Una rechazada no cuenta
        var otro = new MediaStore(new SecureRandom(), MediaStore.CAPACITY);
        for (var i = 0; i < 5; i++) {
            assertThatThrownBy(() -> otro.put("steve", new byte[] {1}, 0)).isInstanceOf(IllegalArgumentException.class);
        }
        otro.put("steve", FOTO, 0);
    }

    @Test
    void venceALaHoraYSaleLaMasViejaSiNoHayLugar() {
        var store = new MediaStore(new SecureRandom(), MediaStore.CAPACITY);
        var id = store.put("steve", FOTO, 1000);
        assertThat(store.get(id, "steve", 4599)).isPresent();
        assertThat(store.get(id, "steve", 4600)).isEmpty();
        assertThat(store.used()).isZero();
        // Compartir algo vencido tampoco vale, aunque sea lo primero que se hace
        var otra = new MediaStore(new SecureRandom(), MediaStore.CAPACITY);
        var vieja = otra.put("steve", FOTO, 1000);
        assertThat(otra.share(vieja, "steve", "alex", 4600)).isFalse();
        // Subir una nueva libera lo vencido
        var tres = new MediaStore(new SecureRandom(), 3L * FOTO.length);
        tres.put("a", FOTO, 0);
        tres.put("b", FOTO, 1);
        tres.put("c", FOTO, 2);
        tres.put("d", FOTO, 3602);
        assertThat(tres.used()).isEqualTo(FOTO.length);
        // Total de 3 imágenes: la cuarta saca a la primera
        var chico = new MediaStore(new SecureRandom(), 3L * FOTO.length);
        var a = chico.put("a", FOTO, 0);
        var b = chico.put("b", FOTO, 1);
        var c = chico.put("c", FOTO, 2);
        assertThat(chico.used()).isEqualTo(3L * FOTO.length);
        var d = chico.put("d", FOTO, 3);
        assertThat(chico.get(a, "a", 3)).isEmpty();
        assertThat(chico.get(b, "b", 3)).isPresent();
        assertThat(chico.get(c, "c", 3)).isPresent();
        assertThat(chico.get(d, "d", 3)).isPresent();
        assertThat(chico.used()).isEqualTo(3L * FOTO.length);
    }

    @Test
    void soloPngDentroDeLosTopes() {
        var store = new MediaStore(new SecureRandom(), MediaStore.CAPACITY);
        assertThatThrownBy(() -> store.put("s", PngInfoTest.png(513, 10, 0), 0)).hasMessage("la imagen mide más de 512×512");
        assertThatThrownBy(() -> store.put("s", PngInfoTest.png(10, 10, 256 * 1024), 0)).hasMessage("la imagen supera los 256 KiB");
        assertThatThrownBy(() -> store.put("s", new byte[] {1, 2, 3}, 0)).hasMessage("no es un PNG");
        store.put("s", PngInfoTest.png(512, 1, 256 * 1024 - 33), 0);
        // Las de los scripts siguen con sus topes (64 KiB, 256×256)
        assertThatThrownBy(() -> dev.sam.common.lua.PngInfo.check(PngInfoTest.png(257, 1, 0))).hasMessage("la imagen mide más de 256×256");
    }
}
