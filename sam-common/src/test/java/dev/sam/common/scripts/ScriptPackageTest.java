package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * El paquete de un script en tránsito (PROTOCOLO.md 5.5): una sola codificación posible por script (así un
 * solo hash), y su ensamblado por fragmentos con los límites de la conexión.
 */
class ScriptPackageTest {

    private static Map<String, byte[]> archivos() {
        var files = new LinkedHashMap<String, byte[]>();
        files.put("main.lua", "sam.log('hola')".getBytes(StandardCharsets.UTF_8));
        files.put("manifest.json", "{}".getBytes(StandardCharsets.UTF_8));
        files.put("ui/panel.lua", "return {}".getBytes(StandardCharsets.UTF_8));
        files.put("assets/icono.png", new byte[] {(byte) 0x89, 'P', 'N', 'G'});
        return files;
    }

    @Test
    void elPaqueteVaYVuelveYNoDependeDelOrdenDeEntrada() {
        var paquete = ScriptPackage.encode(archivos());
        var decodificado = ScriptPackage.decode(paquete);
        assertThat(decodificado.keySet()).containsExactly("assets/icono.png", "main.lua", "manifest.json", "ui/panel.lua");
        assertThat(decodificado.get("main.lua")).isEqualTo("sam.log('hola')".getBytes(StandardCharsets.UTF_8));
        assertThat(ScriptPackage.encode(new TreeMap<>(archivos()))).isEqualTo(paquete);
        assertThat(ScriptPackage.sha256(paquete)).hasSize(32).isEqualTo(ScriptPackage.sha256(ScriptPackage.encode(archivos())));
    }

    private static byte[] crudo(List<String> rutas) {
        var buf = Unpooled.buffer();
        new SamWriter(buf).list(rutas, 257, (w, r) -> w.string(r, 256).bytes(new byte[] {1}, 512 * 1024));
        return ByteBufUtil.getBytes(buf);
    }

    @Test
    void unaCodificacionNoCanonicaSeRechaza() {
        assertThatThrownBy(() -> ScriptPackage.decode(crudo(List.of("b.lua", "a.lua")))).isInstanceOf(ProtocolException.class)
            .hasMessage("paquete con rutas desordenadas o repetidas");
        assertThatThrownBy(() -> ScriptPackage.decode(crudo(List.of("a.lua", "a.lua")))).isInstanceOf(ProtocolException.class);
        assertThatThrownBy(() -> ScriptPackage.decode(crudo(List.of("Main.lua")))).isInstanceOf(ProtocolException.class)
            .hasMessageContaining("ruta de script inválida");
        assertThatThrownBy(() -> ScriptPackage.decode(crudo(List.of("../x.lua")))).isInstanceOf(ProtocolException.class);
        assertThat(ScriptPackage.decode(crudo(List.of("a.lua", "b.lua")))).containsOnlyKeys("a.lua", "b.lua");
    }

    @Test
    void losFragmentosReconstruyenElPaqueteYVerificanSuHash() {
        var grande = new LinkedHashMap<>(archivos());
        grande.put("datos.lua", new byte[300 * 1024]);
        var paquete = ScriptPackage.encode(grande);
        var trozos = ScriptPackage.chunks(paquete);
        assertThat(trozos).hasSize(3);
        assertThat(trozos.get(0)).hasSize(ScriptPackage.CHUNK);
        var sha = ScriptPackage.sha256(paquete);
        var armado = new ScriptPackage.Assembler(Map.of(java.util.HexFormat.of().formatHex(sha), paquete.length));
        assertThat(armado.accept(sha, 0, 3, trozos.get(0))).isEmpty();
        assertThat(armado.accept(sha, 1, 3, trozos.get(1))).isEmpty();
        assertThat(armado.accept(sha, 2, 3, trozos.get(2))).contains(paquete);
        assertThat(armado.done()).isTrue();
    }

    @Test
    void elEnsambladoExigeOrdenHashOfrecidoYTamano() {
        var paquete = ScriptPackage.encode(archivos());
        var sha = ScriptPackage.sha256(paquete);
        var hex = java.util.HexFormat.of().formatHex(sha);
        // Un hash no ofrecido, un índice fuera de orden o un total que cambia: SAM-P002
        var a = new ScriptPackage.Assembler(Map.of(hex, paquete.length));
        assertThatThrownBy(() -> a.accept(new byte[32], 0, 1, paquete)).isInstanceOfSatisfying(ProtocolException.class,
            e -> assertThat(e.code()).isEqualTo("SAM-P002"));
        var b = new ScriptPackage.Assembler(Map.of(hex, paquete.length));
        assertThatThrownBy(() -> b.accept(sha, 1, 2, paquete)).isInstanceOf(ProtocolException.class).hasMessage("fragmento fuera de orden");
        var c = new ScriptPackage.Assembler(Map.of(hex, paquete.length * 2));
        c.accept(sha, 0, 2, paquete);
        assertThatThrownBy(() -> c.accept(sha, 1, 3, paquete)).isInstanceOf(ProtocolException.class).hasMessage("fragmento fuera de orden");
        // Más bytes que lo ofrecido, o un contenido con otro hash
        var d = new ScriptPackage.Assembler(Map.of(hex, paquete.length - 1));
        assertThatThrownBy(() -> d.accept(sha, 0, 1, paquete)).isInstanceOf(ProtocolException.class).hasMessage("el script supera su tamaño");
        var e = new ScriptPackage.Assembler(Map.of(hex, paquete.length));
        var otro = paquete.clone();
        otro[otro.length - 1] ^= 1;
        assertThatThrownBy(() -> e.accept(sha, 0, 1, otro)).isInstanceOf(ProtocolException.class).hasMessage("el script no coincide con su hash");
        // Un tamaño que no se completa no da paquete
        var f = new ScriptPackage.Assembler(Map.of(hex, paquete.length));
        assertThatThrownBy(() -> f.accept(sha, 0, 1, java.util.Arrays.copyOf(paquete, 3))).isInstanceOf(ProtocolException.class)
            .hasMessage("el script no coincide con su hash");
        assertThat(new ScriptPackage.Assembler(Map.of()).done()).isTrue();
        assertThat(new ScriptPackage.Assembler(Map.of(hex, 1)).done()).isFalse();
    }

    @Test
    void losTopesDeTamanoSeExigen() {
        var enorme = new LinkedHashMap<String, byte[]>();
        for (var i = 0; i < 9; i++) {
            enorme.put("d" + i + ".lua", new byte[512 * 1024]);
        }
        assertThatThrownBy(() -> ScriptPackage.encode(enorme)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("el script supera los 4 MiB");
        assertThatThrownBy(() -> new ScriptPackage.Assembler(Map.of("a".repeat(64), ScriptPackage.MAX_TOTAL + 1)))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("la descarga supera los 16 MiB");
        assertThat(ScriptPackage.chunks(new byte[0])).singleElement().satisfies(c -> assertThat(c).isEmpty());
        assertThat(ScriptPackage.chunks(new byte[2 * ScriptPackage.CHUNK])).hasSize(2);
        assertThat(new ScriptPackage.Assembler(Map.of("a".repeat(64), ScriptPackage.MAX_TOTAL)).done()).isFalse();
        // Justo 4 MiB se acepta; un byte más, no
        var justo = new LinkedHashMap<String, byte[]>();
        for (var i = 0; i < 8; i++) {
            justo.put("d" + i + ".lua", new byte[512 * 1024]);
        }
        justo.put("d7.lua", new byte[400 * 1024]);
        var falta = ScriptPackage.MAX_PACKAGE - ScriptPackage.encode(justo).length;
        justo.put("d7.lua", new byte[400 * 1024 + falta]);
        assertThat(ScriptPackage.encode(justo)).hasSize(ScriptPackage.MAX_PACKAGE);
        justo.put("d7.lua", new byte[400 * 1024 + falta + 1]);
        assertThatThrownBy(() -> ScriptPackage.encode(justo)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unFragmentoConTotalCeroSeRechaza() {
        var paquete = ScriptPackage.encode(archivos());
        var sha = ScriptPackage.sha256(paquete);
        var armado = new ScriptPackage.Assembler(Map.of(java.util.HexFormat.of().formatHex(sha), paquete.length));
        assertThatThrownBy(() -> armado.accept(sha, 0, 0, paquete)).isInstanceOf(ProtocolException.class)
            .hasMessage("fragmento fuera de orden");
    }
}
