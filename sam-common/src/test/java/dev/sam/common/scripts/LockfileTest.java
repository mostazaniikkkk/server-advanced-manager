package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;

/**
 * PROTOCOLO.md 8.2: lockfile canónico de un script, lo que cubre la firma.
 *
 * <pre>
 * &lt;ruta&gt;\t&lt;sha256 hex&gt;\n   una línea por archivo, ordenadas por bytes UTF-8 de la ruta,
 *                         excluido el signature.json de la raíz
 * </pre>
 *
 * <p>Vector calculado con una implementación de referencia en Python, independiente.
 */
class LockfileTest {

    private static final String LOCK_ESPERADO = """
        assets/icono.png\tbe45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991
        main.lua\t373de7452fc229c503ef11123bfd815d27ea516f0fe22fab908f4e490d29b09b
        manifest.json\t0b81a9cb125c5c2bb94a33e7556417b6530b63c4f5187b02c68fc422231a5e15
        sub/signature.json\td01d3db53ce07cd9972426c565b7b222a18bdc53b0792d8daece9fe798d585d8
        ui/panel.lua\t1232d8379de77e154ca533689af2e42629dd7574bda5a0a390799849f07607c3
        """;
    private static final String SHA_ESPERADO = "e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d";

    @Test
    void coincideConElVectorDeReferencia() {
        var lock = Lockfile.of(archivosDeReferencia());
        assertThat(new String(lock.canonicalBytes(), StandardCharsets.UTF_8)).isEqualTo(LOCK_ESPERADO);
        assertThat(HexFormat.of().formatHex(lock.sha256())).isEqualTo(SHA_ESPERADO);
    }

    @Test
    void soloSeExcluyeElSignatureJsonDeLaRaiz() {
        var lock = Lockfile.of(archivosDeReferencia());
        assertThat(lock.paths()).extracting(ScriptPath::value)
            .contains("sub/signature.json")
            .doesNotContain("signature.json");
    }

    @Test
    void elOrdenDeInsercionNoImporta() {
        var lista = new ArrayList<>(archivosDeReferencia().entrySet());
        Collections.reverse(lista);
        var alReves = new LinkedHashMap<String, byte[]>();
        lista.forEach(e -> alReves.put(e.getKey(), e.getValue()));
        assertThat(Lockfile.of(alReves).sha256()).isEqualTo(Lockfile.of(archivosDeReferencia()).sha256());
    }

    @Test
    void lasRutasSeOrdenanPorBytes() {
        var archivos = new HashMap<String, byte[]>();
        for (var ruta : new String[] {"ab", "a_b", "a/b", "a.b", "a-b"}) {
            archivos.put(ruta, new byte[0]);
        }
        assertThat(Lockfile.of(archivos).paths()).extracting(ScriptPath::value)
            .containsExactly("a-b", "a.b", "a/b", "a_b", "ab");
    }

    @Test
    void rechazaUnScriptSinArchivos() {
        assertThatThrownBy(() -> Lockfile.of(Map.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Lockfile.of(Map.of("signature.json", new byte[0])))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rechazaMasDe256Archivos() {
        assertThat(Lockfile.of(archivos(256)).paths()).hasSize(256);
        assertThatThrownBy(() -> Lockfile.of(archivos(257)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("256");
    }

    @Test
    void elSignatureJsonDeLaRaizNoCuentaParaElLimite() {
        var archivos = archivos(256);
        archivos.put("signature.json", new byte[0]);
        assertThat(Lockfile.of(archivos).paths()).hasSize(256);
    }

    @Test
    void rechazaRutasInvalidas() {
        assertThatThrownBy(() -> Lockfile.of(Map.of("../fuera.lua", new byte[0])))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("../fuera.lua");
    }

    @Test
    void losBytesCanonicosSonUnaCopia() {
        var lock = Lockfile.of(archivosDeReferencia());
        lock.canonicalBytes()[0] = 'X';
        lock.sha256()[0] ^= 1;
        assertThat(HexFormat.of().formatHex(lock.sha256())).isEqualTo(SHA_ESPERADO);
        assertThat(new String(lock.canonicalBytes(), StandardCharsets.UTF_8)).isEqualTo(LOCK_ESPERADO);
    }

    @Property(tries = 200)
    void cambiarUnByteDeCualquierArchivoCambiaElHash(
            @ForAll @Size(min = 1, max = 64) byte[] contenido, @ForAll @IntRange(max = 63) int posicion) {
        var original = Map.of("main.lua", contenido);
        var modificado = contenido.clone();
        modificado[posicion % contenido.length] ^= 0x01;
        assertThat(Lockfile.of(Map.of("main.lua", modificado)).sha256())
            .isNotEqualTo(Lockfile.of(original).sha256());
    }

    @Test
    void agregarOQuitarUnArchivoCambiaElHash() {
        var base = Lockfile.of(Map.of("main.lua", new byte[0])).sha256();
        assertThat(Lockfile.of(Map.of("main.lua", new byte[0], "extra.lua", new byte[0])).sha256()).isNotEqualTo(base);
        assertThat(Lockfile.of(Map.of("otro.lua", new byte[0])).sha256()).isNotEqualTo(base);
    }

    private static Map<String, byte[]> archivosDeReferencia() {
        var archivos = new LinkedHashMap<String, byte[]>();
        archivos.put("manifest.json", "{\"id\":\"demo\",\"version\":\"1.0.0\"}\n".getBytes(StandardCharsets.UTF_8));
        archivos.put("main.lua", "print(\"hola\")\n".getBytes(StandardCharsets.UTF_8));
        archivos.put("ui/panel.lua", "return {}\n".getBytes(StandardCharsets.UTF_8));
        var png = new byte[16];
        for (int i = 0; i < 16; i++) {
            png[i] = (byte) i;
        }
        archivos.put("assets/icono.png", png);
        archivos.put("signature.json", "ignorado".getBytes(StandardCharsets.UTF_8));
        archivos.put("sub/signature.json", "incluido".getBytes(StandardCharsets.UTF_8));
        return archivos;
    }

    private static Map<String, byte[]> archivos(int cantidad) {
        var archivos = new HashMap<String, byte[]>();
        for (int i = 0; i < cantidad; i++) {
            archivos.put("f" + i + ".lua", new byte[0]);
        }
        return archivos;
    }
}
