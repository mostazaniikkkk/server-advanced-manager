package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
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
import dev.sam.common.proto.scripts.ScriptsConsent;
import dev.sam.common.proto.scripts.ScriptsWant;

/**
 * La entrega de scripts del lado del servidor (PROTOCOLO.md 5.5, RS-LUA-05): la oferta sale del catálogo,
 * se mandan en fragmentos solo los paquetes pedidos y el consentimiento decide según
 * {@code SAM_SCRIPTS_CLIENT_ON_REJECT}.
 */
class ServerDeliveryTest {

    private static final Ed25519PrivateKey OPERADOR = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    private static KeyPair identidad;

    @TempDir
    java.nio.file.Path dir;

    @BeforeAll
    static void clave() throws Exception {
        identidad = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static ScriptCatalog.ClientScript script(String id, boolean required, int relleno) {
        var files = new LinkedHashMap<String, byte[]>();
        files.put("manifest.json", ("{\"id\":\"" + id + "\",\"version\":\"2\",\"side\":\"client\",\"capabilities\":[\"hud\"],\"required\":"
            + required + "}").getBytes(StandardCharsets.UTF_8));
        files.put("main.lua", ("-- " + "x".repeat(relleno)).getBytes(StandardCharsets.UTF_8));
        files.put("signature.json", ScriptSigner.sign(files, OPERADOR));
        return new ScriptCatalog.ClientScript(ScriptManifest.parse(id, files.get("manifest.json")), files);
    }

    private static ServerDelivery.Catalog catalogo() {
        var keylist = KeyList.issue(List.of(new KeyList.Entry(SigningPublicKey.of(OPERADOR.publicKeyRaw()), "operador")),
            identidad.getPrivate(), 5L);
        return ServerDelivery.Catalog.of(List.of(script("hud", true, 10), script("mapa", false, 200 * 1024)), keylist);
    }

    @Test
    void laOfertaDescribeCadaPaqueteYElClienteLaVerifica() {
        var catalogo = catalogo();
        var oferta = catalogo.offer();
        assertThat(oferta.scripts()).extracting(r -> r.id()).containsExactly("hud", "mapa");
        var hud = oferta.scripts().getFirst();
        assertThat(hud.version()).isEqualTo("2");
        assertThat(hud.required()).isTrue();
        assertThat(hud.caps()).containsExactly("hud");
        assertThat(hud.sha256()).isEqualTo(ScriptPackage.sha256(ScriptPackage.encode(script("hud", true, 10).files())));
        assertThat(hud.size()).isEqualTo(ScriptPackage.encode(script("hud", true, 10).files()).length);
        // De punta a punta: lo que manda el servidor lo acepta el cliente
        var entrega = new ServerDelivery(catalogo, ServerDelivery.OnReject.PER_SCRIPT);
        var cliente = ClientDelivery.open(oferta, ServerPublicKey.fromSpki(identidad.getPublic().getEncoded()), new ScriptCache(dir));
        var trozos = entrega.onWant(cliente.want());
        assertThat(trozos).hasSize(3);
        trozos.forEach(cliente::chunk);
        assertThat(cliente.complete()).isTrue();
        assertThat(cliente.ready()).extracting(r -> r.script().manifest().id()).containsExactly("hud", "mapa");
    }

    @Test
    void soloSeMandaLoPedidoYUnaVez() {
        var catalogo = catalogo();
        var mapa = catalogo.offer().scripts().get(1).sha256();
        var entrega = new ServerDelivery(catalogo, ServerDelivery.OnReject.ALLOW);
        assertThat(entrega.onWant(new ScriptsWant(List.of(mapa)))).hasSize(2).allSatisfy(c -> assertThat(c.sha256()).isEqualTo(mapa));
        assertThatThrownBy(() -> entrega.onWant(new ScriptsWant(List.of()))).isInstanceOfSatisfying(ProtocolException.class,
            e -> assertThat(e.code()).isEqualTo("SAM-P002")).hasMessage("scripts_want repetido");
        var otra = new ServerDelivery(catalogo, ServerDelivery.OnReject.ALLOW);
        assertThatThrownBy(() -> otra.onWant(new ScriptsWant(List.of(new byte[32])))).isInstanceOf(ProtocolException.class)
            .hasMessage("pedido de un script no ofrecido");
        var repetido = new ServerDelivery(catalogo, ServerDelivery.OnReject.ALLOW);
        assertThatThrownBy(() -> repetido.onWant(new ScriptsWant(List.of(mapa, mapa)))).isInstanceOf(ProtocolException.class)
            .hasMessage("pedido de un script no ofrecido");
        assertThat(new ServerDelivery(catalogo, ServerDelivery.OnReject.ALLOW).onWant(new ScriptsWant(List.of()))).isEmpty();
    }

    @Test
    void elConsentimientoLlegaDespuesDelPedidoYSoloConIdsOfrecidos() {
        var catalogo = catalogo();
        var antes = new ServerDelivery(catalogo, ServerDelivery.OnReject.ALLOW);
        assertThatThrownBy(() -> antes.onConsent(new ScriptsConsent(List.of()))).isInstanceOfSatisfying(ProtocolException.class,
            e -> assertThat(e.code()).isEqualTo("SAM-P002")).hasMessage("scripts_consent fuera de orden");
        var entrega = new ServerDelivery(catalogo, ServerDelivery.OnReject.ALLOW);
        entrega.onWant(new ScriptsWant(List.of()));
        assertThatThrownBy(() -> entrega.onConsent(new ScriptsConsent(List.of("otro")))).isInstanceOf(ProtocolException.class)
            .hasMessage("consentimiento de un script no ofrecido");
        var dos = new ServerDelivery(catalogo, ServerDelivery.OnReject.ALLOW);
        dos.onWant(new ScriptsWant(List.of()));
        assertThat(dos.onConsent(new ScriptsConsent(List.of("mapa", "hud"))).accepted()).containsExactly("hud", "mapa");
        assertThatThrownBy(() -> dos.onConsent(new ScriptsConsent(List.of()))).isInstanceOf(ProtocolException.class)
            .hasMessage("scripts_consent fuera de orden");
        assertThatThrownBy(() -> dos.onWant(new ScriptsWant(List.of()))).isInstanceOf(ProtocolException.class);
    }

    private static ServerDelivery.Reply consentir(ServerDelivery.OnReject politica, String... ids) {
        var entrega = new ServerDelivery(catalogo(), politica);
        entrega.onWant(new ScriptsWant(List.of()));
        return entrega.onConsent(new ScriptsConsent(List.of(ids)));
    }

    @Test
    void laPoliticaDeRechazoDecideLaExpulsion() {
        var kick = "Debes aceptar los scripts requeridos. [SAM-K010]";
        assertThat(consentir(ServerDelivery.OnReject.KICK, "hud", "mapa").kick()).isEmpty();
        assertThat(consentir(ServerDelivery.OnReject.KICK, "hud").kick()).contains(kick);
        assertThat(consentir(ServerDelivery.OnReject.PER_SCRIPT, "hud").kick()).isEmpty();
        assertThat(consentir(ServerDelivery.OnReject.PER_SCRIPT, "mapa").kick()).contains(kick);
        assertThat(consentir(ServerDelivery.OnReject.ALLOW).kick()).isEmpty();
        assertThat(consentir(ServerDelivery.OnReject.ALLOW).accepted()).isEmpty();
        assertThat(ServerDelivery.OnReject.parse(" Per_Script ")).isEqualTo(ServerDelivery.OnReject.PER_SCRIPT);
        assertThat(ServerDelivery.OnReject.parse("kick")).isEqualTo(ServerDelivery.OnReject.KICK);
        assertThatThrownBy(() -> ServerDelivery.OnReject.parse("nunca")).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("SAM_SCRIPTS_CLIENT_ON_REJECT debe ser kick, allow o per_script");
    }

    @Test
    void elCatalogoRespetaLosTopesDeLaConexion() {
        var keylist = KeyList.issue(List.of(), identidad.getPrivate(), 5L);
        assertThat(ServerDelivery.Catalog.of(List.of(), keylist).offer().scripts()).isEmpty();
        var muchos = new java.util.ArrayList<ScriptCatalog.ClientScript>();
        for (var i = 0; i < 129; i++) {
            muchos.add(script("s" + i, false, 0));
        }
        assertThatThrownBy(() -> ServerDelivery.Catalog.of(muchos, keylist)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("hay más de 128 scripts de cliente");
        var grandes = new java.util.ArrayList<ScriptCatalog.ClientScript>();
        for (var i = 0; i < 5; i++) {
            var files = new LinkedHashMap<String, byte[]>();
            files.put("manifest.json", ("{\"id\":\"g" + i + "\",\"version\":\"1\",\"side\":\"client\"}").getBytes(StandardCharsets.UTF_8));
            for (var j = 0; j < 7; j++) {
                files.put("d" + j + ".lua", new byte[500 * 1024]);
            }
            grandes.add(new ScriptCatalog.ClientScript(ScriptManifest.parse("g" + i, files.get("manifest.json")), files));
        }
        assertThatThrownBy(() -> ServerDelivery.Catalog.of(grandes, keylist)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("los scripts de cliente suman más de 16 MiB");
        assertThat(ServerDelivery.Catalog.of(grandes.subList(0, 4), keylist).offer().scripts()).hasSize(4);
        assertThat(ServerDelivery.Catalog.of(List.of(script("hud", true, 0)), keylist).packages()).hasSize(1);
        assertThat(ServerDelivery.Catalog.of(muchos.subList(0, 128), keylist).offer().scripts()).hasSize(128);
        // Justo 16 MiB caben: cuatro paquetes de justo 4 MiB
        var justos = new java.util.ArrayList<ScriptCatalog.ClientScript>();
        for (var i = 0; i < 4; i++) {
            var files = new LinkedHashMap<>(grandes.get(i).files());
            files.put("r0.lua", new byte[300 * 1024]);
            files.put("relleno.lua", new byte[0]);
            var falta = ScriptPackage.MAX_PACKAGE - ScriptPackage.encode(files).length;
            files.put("relleno.lua", new byte[falta - 2]);
            justos.add(new ScriptCatalog.ClientScript(grandes.get(i).manifest(), files));
        }
        assertThat(justos).allSatisfy(j -> assertThat(ScriptPackage.encode(j.files())).hasSize(ScriptPackage.MAX_PACKAGE));
        assertThat(ServerDelivery.Catalog.of(justos, keylist).offer().scripts()).hasSize(4);
        var unico = Map.copyOf(ServerDelivery.Catalog.of(List.of(script("hud", true, 0)), keylist).packages());
        assertThat(unico.keySet()).allSatisfy(h -> assertThat(h).hasSize(64));
    }
}
