package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sam.common.crypto.Ed25519PrivateKey;
import dev.sam.common.identity.ServerPublicKey;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.scripts.ScriptChunk;
import dev.sam.common.proto.scripts.ScriptRef;
import dev.sam.common.proto.scripts.ScriptsOffer;

/**
 * La entrega de scripts del lado del cliente (RF-LUA-05, RS-SIG-05/06, RN-31): solo valen los scripts
 * firmados por una clave de la keylist que firmó el servidor fijado, la caché es por hash y se verifica en
 * cada carga, y lo que ya no verifica se borra y se pide de nuevo.
 */
class ClientDeliveryTest {

    private static final Ed25519PrivateKey OPERADOR = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    private static final Ed25519PrivateKey AJENA = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    private static KeyPair servidor;
    private static KeyPair otroServidor;

    @TempDir
    Path dir;

    @BeforeAll
    static void identidades() throws Exception {
        servidor = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        otroServidor = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static ServerPublicKey fijada() {
        return ServerPublicKey.fromSpki(servidor.getPublic().getEncoded());
    }

    private static SignedBlob keylist(KeyPair firmante, Ed25519PrivateKey... claves) {
        var entries = java.util.Arrays.stream(claves)
            .map(c -> new KeyList.Entry(SigningPublicKey.of(c.publicKeyRaw()), c == OPERADOR ? "operador" : "ajena")).toList();
        return KeyList.issue(entries, firmante.getPrivate(), 1L);
    }

    private static Map<String, byte[]> script(String id, String side, String main, Ed25519PrivateKey clave) {
        var files = new LinkedHashMap<String, byte[]>();
        files.put("manifest.json", ("{\"id\":\"" + id + "\",\"version\":\"1.0\",\"side\":\"" + side
            + "\",\"capabilities\":[\"hud\"],\"required\":true}").getBytes(StandardCharsets.UTF_8));
        files.put("main.lua", main.getBytes(StandardCharsets.UTF_8));
        files.put("signature.json", ScriptSigner.sign(files, clave));
        return files;
    }

    private static byte[] paquete(Map<String, byte[]> files) {
        return ScriptPackage.encode(files);
    }

    private static ScriptRef ref(String id, byte[] paquete) {
        return new ScriptRef(id, "1.0", ScriptPackage.sha256(paquete), paquete.length, true, List.of("hud"));
    }

    private static void enviar(ClientDelivery entrega, byte[] paquete) {
        var trozos = ScriptPackage.chunks(paquete);
        for (var i = 0; i < trozos.size(); i++) {
            entrega.chunk(new ScriptChunk(ScriptPackage.sha256(paquete), i, trozos.size(), trozos.get(i)));
        }
    }

    private static List<String> hex(ClientDelivery entrega) {
        return entrega.want().hashes().stream().map(HexFormat.of()::formatHex).toList();
    }

    @Test
    void sinCacheSePideYAlLlegarQuedaListoYGuardado() {
        var hud = paquete(script("hud", "client", "sam.log('ñandú')", OPERADOR));
        var cache = new ScriptCache(dir);
        var entrega = ClientDelivery.open(new ScriptsOffer(keylist(servidor, OPERADOR), List.of(ref("hud", hud))), fijada(), cache);
        assertThat(hex(entrega)).containsExactly(HexFormat.of().formatHex(ScriptPackage.sha256(hud)));
        assertThat(entrega.complete()).isFalse();
        assertThat(entrega.ready()).isEmpty();
        assertThat(entrega.failed()).isEmpty();
        enviar(entrega, hud);
        assertThat(entrega.complete()).isTrue();
        assertThat(entrega.failed()).isEmpty();
        var listo = entrega.ready().getFirst();
        assertThat(listo.signer()).isEqualTo("operador");
        assertThat(listo.script().manifest().capabilities()).containsExactly("hud");
        assertThat(listo.script().sources()).containsEntry("main.lua", "sam.log('ñandú')");
        assertThat(cache.read(HexFormat.of().formatHex(ScriptPackage.sha256(hud)))).contains(hud);
        // La próxima conexión no pide nada: sale de la caché, verificado de nuevo
        var otra = ClientDelivery.open(new ScriptsOffer(keylist(servidor, AJENA, OPERADOR), List.of(ref("hud", hud))), fijada(), cache);
        assertThat(otra.want().hashes()).isEmpty();
        assertThat(otra.ready().getFirst().signer()).isEqualTo("operador");
        assertThat(otra.complete()).isTrue();
        assertThat(otra.ready()).extracting(r -> r.script().manifest().id()).containsExactly("hud");
    }

    @Test
    void unaKeylistQueNoFirmoElServidorFijadoRechazaLaOferta() {
        var hud = paquete(script("hud", "client", "", OPERADOR));
        var oferta = new ScriptsOffer(keylist(otroServidor, OPERADOR), List.of(ref("hud", hud)));
        assertThatThrownBy(() -> ClientDelivery.open(oferta, fijada(), new ScriptCache(dir)))
            .isInstanceOfSatisfying(ProtocolException.class, e -> assertThat(e.code()).isEqualTo("SAM-P001"))
            .hasMessage("la lista de claves no la firmó este servidor");
    }

    @Test
    void unaOfertaConScriptsRepetidosOMasDe16MiBSeRechaza() {
        var a = paquete(script("a", "client", "", OPERADOR));
        var b = paquete(script("b", "client", "", OPERADOR));
        var kl = keylist(servidor, OPERADOR);
        assertThatThrownBy(() -> ClientDelivery.open(new ScriptsOffer(kl, List.of(ref("a", a), ref("a", b))), fijada(), new ScriptCache(dir)))
            .isInstanceOf(ProtocolException.class).hasMessage("oferta con scripts repetidos");
        assertThatThrownBy(() -> ClientDelivery.open(new ScriptsOffer(kl, List.of(ref("a", a), ref("b", a))), fijada(), new ScriptCache(dir)))
            .isInstanceOf(ProtocolException.class).hasMessage("oferta con scripts repetidos");
        var refs = new java.util.ArrayList<ScriptRef>();
        for (var i = 0; i < 5; i++) {
            var sha = new byte[32];
            sha[0] = (byte) i;
            refs.add(new ScriptRef("s" + i, "1", sha, ScriptRef.MAX_SIZE, false, List.of()));
        }
        assertThatThrownBy(() -> ClientDelivery.open(new ScriptsOffer(kl, refs), fijada(), new ScriptCache(dir)))
            .isInstanceOf(ProtocolException.class).hasMessage("la descarga supera los 16 MiB");
        assertThat(ClientDelivery.open(new ScriptsOffer(kl, refs.subList(0, 4)), fijada(), new ScriptCache(dir)).want().hashes()).hasSize(4);
    }

    @Test
    void loQueNoVerificaAlLlegarFallaYNoSeGuarda() {
        var kl = keylist(servidor, OPERADOR);
        var ajeno = paquete(script("ajeno", "client", "", AJENA));
        var deServidor = paquete(script("srv", "server", "", OPERADOR));
        var mentiroso = paquete(script("otro", "client", "", OPERADOR));
        var basura = new byte[] {1, 2, 3};
        var sinManifest = paquete(Map.of("main.lua", new byte[0]));
        var malManifest = paquete(Map.of("manifest.json", "{}".getBytes(StandardCharsets.UTF_8)));
        var noUtf8 = new LinkedHashMap<String, byte[]>();
        noUtf8.put("manifest.json", "{\"id\":\"latin\",\"version\":\"1.0\",\"side\":\"client\",\"capabilities\":[\"hud\"],\"required\":true}"
            .getBytes(StandardCharsets.UTF_8));
        noUtf8.put("main.lua", new byte[] {(byte) 0xFF});
        noUtf8.put("signature.json", ScriptSigner.sign(noUtf8, OPERADOR));
        var latin = paquete(noUtf8);
        var cache = new ScriptCache(dir);
        var entrega = ClientDelivery.open(new ScriptsOffer(kl, List.of(ref("ajeno", ajeno), ref("srv", deServidor), ref("mentira", mentiroso),
            ref("basura", basura), ref("sinmanifest", sinManifest), ref("malmanifest", malManifest), ref("latin", latin))), fijada(), cache);
        for (var p : List.of(ajeno, deServidor, mentiroso, basura, sinManifest, malManifest, latin)) {
            enviar(entrega, p);
        }
        assertThat(entrega.complete()).isTrue();
        assertThat(entrega.ready()).isEmpty();
        assertThat(entrega.failed()).containsExactly(
            new ScriptCatalog.Rejected("ajeno", "lo firmó una clave que no es de confianza"),
            new ScriptCatalog.Rejected("srv", "no es un script de cliente"),
            new ScriptCatalog.Rejected("mentira", "manifest.json inválido: el id \"otro\" no coincide con la carpeta \"mentira\""),
            new ScriptCatalog.Rejected("basura", "el paquete está mal formado"),
            new ScriptCatalog.Rejected("sinmanifest", "falta manifest.json"),
            new ScriptCatalog.Rejected("malmanifest", "manifest.json inválido: faltan id, version o side"),
            new ScriptCatalog.Rejected("latin", "main.lua no es UTF-8 válido"));
        assertThat(dir).isEmptyDirectory();
    }

    @Test
    void loAnunciadoDebeCoincidirConElManifestFirmado() {
        var kl = keylist(servidor, OPERADOR);
        var hud = paquete(script("hud", "client", "", OPERADOR));
        var sha = ScriptPackage.sha256(hud);
        var variantes = List.of(new ScriptRef("hud", "2.0", sha, hud.length, true, List.of("hud")),
            new ScriptRef("hud", "1.0", sha, hud.length, false, List.of("hud")),
            new ScriptRef("hud", "1.0", sha, hud.length, true, List.of("hud", "screens")));
        for (var variante : variantes) {
            var entrega = ClientDelivery.open(new ScriptsOffer(kl, List.of(variante)), fijada(), new ScriptCache(dir));
            enviar(entrega, hud);
            assertThat(entrega.failed()).as(variante.toString())
                .containsExactly(new ScriptCatalog.Rejected("hud", "no coincide con lo que anunció el servidor"));
        }
    }

    @Test
    void enCadaCargaLaCacheSeVerificaDeNuevoYLoRevocadoSeBorra() throws Exception {
        var hud = paquete(script("hud", "client", "", OPERADOR));
        var hexHud = HexFormat.of().formatHex(ScriptPackage.sha256(hud));
        var cache = new ScriptCache(dir);
        cache.write(hud);
        // La clave ya no está en la keylist (RS-SIG-06): se borra de la caché y se pide de nuevo
        var sinOperador = ClientDelivery.open(new ScriptsOffer(keylist(servidor, AJENA), List.of(ref("hud", hud))), fijada(), cache);
        assertThat(hex(sinOperador)).containsExactly(hexHud);
        assertThat(cache.read(hexHud)).isEmpty();
        enviar(sinOperador, hud);
        assertThat(sinOperador.failed()).extracting(ScriptCatalog.Rejected::reason).containsExactly("lo firmó una clave que no es de confianza");
        assertThat(cache.read(hexHud)).isEmpty();
        // Un archivo alterado en la caché no coincide con su hash: se descarta (RN-31)
        cache.write(hud);
        var archivo = dir.resolve(hexHud);
        var alterado = Files.readAllBytes(archivo);
        alterado[alterado.length - 1] ^= 1;
        Files.write(archivo, alterado);
        var entrega = ClientDelivery.open(new ScriptsOffer(keylist(servidor, OPERADOR), List.of(ref("hud", hud))), fijada(), cache);
        assertThat(hex(entrega)).containsExactly(hexHud);
        assertThat(archivo).doesNotExist();
    }

    @Test
    void laCacheEsPorHash() throws Exception {
        var cache = new ScriptCache(dir.resolve("anidada"));
        assertThat(cache.read("00".repeat(32))).isEmpty();
        var bytes = new byte[] {4, 5, 6};
        var hexBytes = HexFormat.of().formatHex(ScriptPackage.sha256(bytes));
        cache.write(bytes);
        cache.write(bytes);
        assertThat(cache.read(hexBytes)).contains(bytes);
        assertThat(Files.list(dir.resolve("anidada")).map(p -> p.getFileName().toString())).containsExactly(hexBytes);
        var alterado = new byte[] {4, 5, 7};
        Files.write(dir.resolve("anidada").resolve(hexBytes), alterado);
        assertThat(cache.read(hexBytes)).isEmpty();
        assertThat(dir.resolve("anidada").resolve(hexBytes)).doesNotExist();
        cache.write(bytes);
        cache.delete(hexBytes);
        cache.delete(hexBytes);
        assertThat(cache.read(hexBytes)).isEmpty();
        assertThatThrownBy(() -> cache.read("../x")).isInstanceOf(IllegalArgumentException.class).hasMessage("hash inválido: ../x");
        assertThatThrownBy(() -> cache.read("AB".repeat(32))).isInstanceOf(IllegalArgumentException.class);
        // Un archivo más grande que un paquete no se lee: se borra
        var grande = new byte[ScriptPackage.MAX_PACKAGE + 1];
        var hexGrande = HexFormat.of().formatHex(ScriptPackage.sha256(grande));
        Files.write(dir.resolve("anidada").resolve(hexGrande), grande);
        assertThat(cache.read(hexGrande)).isEmpty();
        assertThat(dir.resolve("anidada").resolve(hexGrande)).doesNotExist();
        // Justo el máximo sí se lee
        var justo = new byte[ScriptPackage.MAX_PACKAGE];
        cache.write(justo);
        assertThat(cache.read(HexFormat.of().formatHex(ScriptPackage.sha256(justo)))).contains(justo);
    }
}
