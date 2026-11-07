package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.crypto.Ed25519PrivateKey;

/**
 * El catálogo de scripts del servidor (RF-LUA-01, RS-SIG-01/02/04): de lo que hay en los datapacks a los
 * scripts que corren, en orden de dependencias. Sin firma de confianza no corre nada, salvo en modo
 * desarrollo y solo del lado servidor.
 */
class ScriptCatalogTest {

    private static final Ed25519PrivateKey CLAVE = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    private static final Ed25519PrivateKey AJENA = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    private static final List<SigningPublicKey> CONFIANZA = List.of(SigningPublicKey.of(CLAVE.publicKeyRaw()));

    private static Map<String, byte[]> archivos(String id, String side, String deps, String main) {
        var files = new LinkedHashMap<String, byte[]>();
        files.put("manifest.json", ("{\"id\":\"" + id + "\",\"version\":\"1\",\"side\":\"" + side + "\",\"dependencies\":[" + deps
            + "]}").getBytes(StandardCharsets.UTF_8));
        files.put("main.lua", main.getBytes(StandardCharsets.UTF_8));
        return files;
    }

    private static Map<String, byte[]> firmado(Map<String, byte[]> files, Ed25519PrivateKey clave) {
        var conFirma = new LinkedHashMap<>(files);
        conFirma.put("signature.json", ScriptSigner.sign(files, clave));
        return conFirma;
    }

    private static Map<String, byte[]> servidor(String id, String deps) {
        return firmado(archivos(id, "server", deps, "sam.log('" + id + "')"), CLAVE);
    }

    private static List<String> ids(ScriptCatalog.Result r) {
        return r.server().stream().map(p -> p.manifest().id()).toList();
    }

    @Test
    void losFirmadosConUnaClaveDeConfianzaCarganConSusFuentes() {
        var archivos = archivos("hola", "server", "", "sam.log('canción')");
        archivos.put("util.lua", "return 1".getBytes(StandardCharsets.UTF_8));
        archivos.put("assets/icono.png", new byte[] {(byte) 0x89, 'P', 'N', 'G'});
        var r = ScriptCatalog.build(Map.of("hola", firmado(archivos, CLAVE)), CONFIANZA, false);
        assertThat(r.rejected()).isEmpty();
        assertThat(r.warnings()).isEmpty();
        var hola = r.server().getFirst();
        assertThat(hola.manifest().id()).isEqualTo("hola");
        assertThat(hola.sources()).containsOnlyKeys("main.lua", "util.lua").containsEntry("main.lua", "sam.log('canción')");
    }

    @Test
    void sinFirmaDeConfianzaNoCarga() {
        var r = ScriptCatalog.build(Map.of(
            "sinfirma", archivos("sinfirma", "server", "", ""),
            "ajena", firmado(archivos("ajena", "server", "", ""), AJENA),
            "alterado", alterado()), CONFIANZA, false);
        assertThat(r.server()).isEmpty();
        assertThat(r.rejected()).containsExactlyInAnyOrder(
            new ScriptCatalog.Rejected("sinfirma", "no está firmado"),
            new ScriptCatalog.Rejected("ajena", "lo firmó una clave que no es de confianza"),
            new ScriptCatalog.Rejected("alterado", "sus archivos no coinciden con la firma (alguno se agregó, quitó o cambió)"));
    }

    private static Map<String, byte[]> alterado() {
        var files = firmado(archivos("alterado", "server", "", "sam.log(1)"), CLAVE);
        files.put("main.lua", "sam.log(2)".getBytes(StandardCharsets.UTF_8));
        return files;
    }

    @Test
    void elModoDesarrolloAceptaSinFirmaSoloDelLadoServidor() {
        var r = ScriptCatalog.build(Map.of(
            "dev", archivos("dev", "server", "", ""),
            "cliente", archivos("cliente", "client", "", ""),
            "ambos", archivos("ambos", "both", "", "")), CONFIANZA, true);
        assertThat(ids(r)).containsExactly("dev");
        assertThat(r.warnings()).containsExactly("El script dev no está firmado: solo corre porque el modo desarrollo está activo");
        assertThat(r.rejected()).extracting(ScriptCatalog.Rejected::id).containsExactlyInAnyOrder("cliente", "ambos");
        // Aun en modo desarrollo, una firma inválida no se tolera
        var malo = ScriptCatalog.build(Map.of("alterado", alterado()), CONFIANZA, true);
        assertThat(malo.server()).isEmpty();
    }

    @Test
    void losScriptsDeClienteNoCorrenEnElServidor() {
        var r = ScriptCatalog.build(Map.of("ui", firmado(archivos("ui", "client", "", ""), CLAVE),
            "mixto", firmado(archivos("mixto", "both", "", ""), CLAVE)), CONFIANZA, false);
        assertThat(ids(r)).containsExactly("mixto");
        assertThat(r.rejected()).isEmpty();
    }

    @Test
    void seCarganEnOrdenDeDependencias() {
        var r = ScriptCatalog.build(Map.of(
            "tienda", servidor("tienda", "\"economia\",\"base\""),
            "economia", servidor("economia", "\"base\""),
            "base", servidor("base", ""),
            "zeta", servidor("zeta", "")), CONFIANZA, false);
        assertThat(ids(r)).containsExactly("base", "economia", "tienda", "zeta");
    }

    @Test
    void unaDependenciaQueFaltaOCircularRechaza() {
        var r = ScriptCatalog.build(Map.of(
            "huerfano", servidor("huerfano", "\"nadie\""),
            "a", servidor("a", "\"b\""),
            "b", servidor("b", "\"a\""),
            "nieto", servidor("nieto", "\"huerfano\""),
            "sano", servidor("sano", "")), CONFIANZA, false);
        assertThat(ids(r)).containsExactly("sano");
        assertThat(r.rejected()).containsExactlyInAnyOrder(
            new ScriptCatalog.Rejected("huerfano", "depende de nadie, que no está disponible"),
            new ScriptCatalog.Rejected("nieto", "depende de huerfano, que no está disponible"),
            new ScriptCatalog.Rejected("a", "dependencia circular"),
            new ScriptCatalog.Rejected("b", "dependencia circular"));
    }

    @Test
    void loMalFormadoSeRechazaConSuMotivo() {
        var sinManifest = new LinkedHashMap<String, byte[]>();
        sinManifest.put("main.lua", new byte[0]);
        var rutaMala = archivos("ruta", "server", "", "");
        rutaMala.put("Main.lua", new byte[0]);
        var utf8Malo = archivos("bytes", "server", "", "");
        utf8Malo.put("main.lua", new byte[] {(byte) 0xff, (byte) 0xfe});
        var r = ScriptCatalog.build(Map.of(
            "Mayus", archivos("Mayus", "server", "", ""),
            "vacio", sinManifest,
            "otro", archivos("distinto", "server", "", ""),
            "ruta", rutaMala,
            "bytes", firmado(utf8Malo, CLAVE),
            "firma", firmadoConBasura()), CONFIANZA, true);
        assertThat(r.server()).isEmpty();
        assertThat(r.rejected()).containsExactlyInAnyOrder(
            new ScriptCatalog.Rejected("Mayus", "el nombre de la carpeta debe ser [a-z0-9_], hasta 32"),
            new ScriptCatalog.Rejected("vacio", "falta manifest.json"),
            new ScriptCatalog.Rejected("otro", "manifest.json inválido: el id \"distinto\" no coincide con la carpeta \"otro\""),
            new ScriptCatalog.Rejected("ruta", "tiene archivos con rutas inválidas o demasiados archivos"),
            new ScriptCatalog.Rejected("bytes", "main.lua no es UTF-8 válido"),
            new ScriptCatalog.Rejected("firma", "signature.json está mal formado"));
    }

    private static Map<String, byte[]> firmadoConBasura() {
        var files = archivos("firma", "server", "", "");
        files.put("signature.json", "{}".getBytes(StandardCharsets.UTF_8));
        return files;
    }
}
