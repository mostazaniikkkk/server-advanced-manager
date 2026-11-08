package dev.sam.signer;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sam.common.scripts.ScriptCatalog;
import dev.sam.common.scripts.TrustStore;

/**
 * La línea de comandos de sam-signer (RS-SIG-01/07): generar la clave del operador, firmar la carpeta de
 * un script y verificarla. Lo firmado lo acepta el catálogo del servidor con esa clave confirmada.
 */
class SamSignerTest {

    @TempDir
    Path dir;

    private final ByteArrayOutputStream salida = new ByteArrayOutputStream();
    private final ArrayDeque<char[]> frases = new ArrayDeque<>();

    private int run(String... args) {
        return SamSigner.run(args, new SamSigner.Env(dir, new PrintStream(salida, true, StandardCharsets.UTF_8),
            prompt -> frases.isEmpty() ? null : frases.poll(), new SecureRandom(), 1000, name -> null));
    }

    private String texto() {
        return salida.toString(StandardCharsets.UTF_8);
    }

    private Path script(String id, String main) throws Exception {
        var carpeta = dir.resolve("data/demo/sam_scripts/" + id);
        Files.createDirectories(carpeta.resolve("ui"));
        Files.writeString(carpeta.resolve("manifest.json"), "{\"id\":\"" + id + "\",\"version\":\"1\",\"side\":\"server\"}");
        Files.writeString(carpeta.resolve("main.lua"), main);
        Files.writeString(carpeta.resolve("ui/panel.lua"), "return {}");
        return carpeta;
    }

    @Test
    void keygenCreaLaClaveCifradaYLaPublica() throws Exception {
        frases.add("frase muy segura 1".toCharArray());
        frases.add("frase muy segura 1".toCharArray());
        assertThat(run("keygen", "steve")).isZero();
        assertThat(Files.readString(dir.resolve("steve.key"))).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        assertThat(Files.readString(dir.resolve("steve.pub"))).startsWith("# Clave de firma de scripts de SAM: steve");
        assertThat(texto()).contains("steve.key").contains("steve.pub").contains("key_id");
        // No pisa una clave existente
        frases.add("frase muy segura 1".toCharArray());
        frases.add("frase muy segura 1".toCharArray());
        assertThat(run("keygen", "steve")).isEqualTo(1);
        assertThat(texto()).contains("ya existe");
    }

    @Test
    void keygenPideLaPassphraseDosVecesYLargas() throws Exception {
        frases.add("frase muy segura 1".toCharArray());
        frases.add("otra frase distinta".toCharArray());
        assertThat(run("keygen", "a")).isEqualTo(1);
        assertThat(texto()).contains("no coinciden");
        frases.add("corta".toCharArray());
        frases.add("corta".toCharArray());
        assertThat(run("keygen", "b")).isEqualTo(1);
        assertThat(texto()).contains("al menos 12");
        assertThat(run("keygen", "c")).isEqualTo(1);
        assertThat(texto()).contains("passphrase");
        assertThat(Files.exists(dir.resolve("a.key"))).isFalse();
    }

    @Test
    void firmarYVerificarUnScriptQueElServidorAcepta() throws Exception {
        frases.add("frase muy segura 1".toCharArray());
        frases.add("frase muy segura 1".toCharArray());
        run("keygen", "steve");
        var carpeta = script("saludo", "sam.log('hola')");
        frases.add("frase muy segura 1".toCharArray());
        assertThat(run("sign", carpeta.toString(), "--key", dir.resolve("steve.key").toString())).isZero();
        assertThat(Files.exists(carpeta.resolve("signature.json"))).isTrue();
        assertThat(texto()).contains("Firmado saludo");
        assertThat(run("verify", carpeta.toString(), "--pub", dir.resolve("steve.pub").toString())).isZero();
        assertThat(texto()).contains("Firma válida");

        // El servidor, con esa clave confirmada, lo carga sin modo desarrollo
        var keys = dir.resolve("server/config/sam/keys");
        Files.createDirectories(keys.resolve("trusted"));
        Files.copy(dir.resolve("steve.pub"), keys.resolve("trusted/steve.pub"));
        var trust = TrustStore.load(keys);
        TrustStore.confirm(keys, trust.pending().getFirst().keyId());
        var catalogo = ScriptCatalog.build(Map.of("saludo", SamSigner.readFolder(carpeta)), TrustStore.load(keys).active(), false);
        assertThat(catalogo.rejected()).isEmpty();
        assertThat(catalogo.server()).extracting(p -> p.manifest().id()).containsExactly("saludo");

        // Cambiar un archivo después de firmar: la verificación falla
        Files.writeString(carpeta.resolve("main.lua"), "sam.log('cambiado')");
        assertThat(run("verify", carpeta.toString(), "--pub", dir.resolve("steve.pub").toString())).isEqualTo(1);
        assertThat(texto()).contains("no coinciden con la firma");
    }

    @Test
    void firmarConLaPassphraseMalaOUnaCarpetaInvalidaFalla() throws Exception {
        frases.add("frase muy segura 1".toCharArray());
        frases.add("frase muy segura 1".toCharArray());
        run("keygen", "steve");
        var carpeta = script("saludo", "x");
        frases.add("otra frase cualquiera".toCharArray());
        assertThat(run("sign", carpeta.toString(), "--key", dir.resolve("steve.key").toString())).isEqualTo(1);
        assertThat(texto()).contains("passphrase incorrecta");
        assertThat(Files.exists(carpeta.resolve("signature.json"))).isFalse();
        var otra = dir.resolve("data/demo/sam_scripts/otro");
        Files.createDirectories(otra);
        Files.writeString(otra.resolve("manifest.json"), "{\"id\":\"distinto\",\"version\":\"1\",\"side\":\"server\"}");
        frases.add("frase muy segura 1".toCharArray());
        assertThat(run("sign", otra.toString(), "--key", dir.resolve("steve.key").toString())).isEqualTo(1);
        assertThat(texto()).contains("no coincide con la carpeta");
    }

    @Test
    void sinArgumentosOConUnComandoDesconocidoMuestraLaAyuda() {
        assertThat(run()).isEqualTo(2);
        assertThat(texto()).contains("sam-signer keygen <nombre>").contains("sign <carpeta> --key").contains("verify <carpeta> --pub");
        assertThat(run("borrar")).isEqualTo(2);
        assertThat(run("sign", "x")).isEqualTo(2);
        assertThat(run("verify", "x", "--pub")).isEqualTo(2);
    }

    @Test
    void lasPassphrasesSeBorranDeLaMemoriaYLaClaveSoloLaLeeElDueno() throws Exception {
        var a = "frase muy segura 1".toCharArray();
        var b = "frase muy segura 1".toCharArray();
        frases.add(a);
        frases.add(b);
        run("keygen", "steve");
        assertThat(a).containsOnly('\0');
        assertThat(b).containsOnly('\0');
        soloElDueno(dir.resolve("steve.key"));
        assertThat(texto()).contains("config/sam/keys/trusted/");
        var carpeta = script("borra", "x");
        var c = "frase muy segura 1".toCharArray();
        frases.add(c);
        run("sign", carpeta.toString(), "--key", dir.resolve("steve.key").toString());
        assertThat(c).containsOnly('\0');
    }

    @Test
    void losErroresDeCadaComandoSeExplican() throws Exception {
        assertThat(run("keygen", "con espacio")).isEqualTo(1);
        assertThat(texto()).contains("[A-Za-z0-9_-]");
        Files.writeString(dir.resolve("solo.key"), "x");
        frases.add("frase muy segura 1".toCharArray());
        frases.add("frase muy segura 1".toCharArray());
        assertThat(run("keygen", "solo")).isEqualTo(1);
        Files.delete(dir.resolve("solo.key"));
        Files.writeString(dir.resolve("solo.pub"), "x");
        frases.add("frase muy segura 1".toCharArray());
        frases.add("frase muy segura 1".toCharArray());
        assertThat(run("keygen", "solo")).isEqualTo(1);
        assertThat(texto()).contains("ya existe");
        var sinManifest = dir.resolve("data/demo/sam_scripts/vacio");
        Files.createDirectories(sinManifest);
        Files.writeString(sinManifest.resolve("main.lua"), "x");
        assertThat(run("sign", sinManifest.toString(), "--key", "x.key")).isEqualTo(1);
        assertThat(texto()).contains("falta manifest.json");
        var carpeta = script("ver", "x");
        assertThat(run("verify", carpeta.toString(), "--x", "a.pub")).isEqualTo(1);
        assertThat(texto()).contains("se esperaba --pub");
        Files.writeString(dir.resolve("mala.pub"), "no es base64!");
        assertThat(run("verify", carpeta.toString(), "--pub", dir.resolve("mala.pub").toString())).isEqualTo(1);
        assertThat(texto()).contains("no es una clave pública");
        assertThat(run("verify", carpeta.toString(), "--pub", dir.resolve("solo.pub").toString(), "x")).isEqualTo(2);
        assertThat(run("sign", carpeta.toString(), "--clave", "x.key")).isEqualTo(2);
        assertThat(run("firmar", carpeta.toString(), "--key", "x.key")).isEqualTo(2);
        assertThat(run("verificar", carpeta.toString(), "--pub", "x.pub")).isEqualTo(2);
    }

    /** La clave privada solo la puede leer el dueño: ACL de una sola entrada (Windows) o permisos 600 (POSIX). */
    private static void soloElDueno(Path file) throws Exception {
        var acl = Files.getFileAttributeView(file, java.nio.file.attribute.AclFileAttributeView.class);
        if (acl != null) {
            assertThat(acl.getAcl()).singleElement().satisfies(e -> assertThat(e.principal()).isEqualTo(acl.getOwner()));
        } else {
            assertThat(Files.getPosixFilePermissions(file)).containsExactlyInAnyOrder(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
        }
    }

    @Test
    void sinConsolaLaPassphrasePuedeVenirDelEntorno() {
        assertThat(SamSigner.fromEnvironment(Map.of("SAM_SIGNER_PASSPHRASE", "frase de ci"))).containsExactly("frase de ci".toCharArray());
        assertThat(SamSigner.fromEnvironment(Map.of())).isNull();
    }

    @Test
    void siLaConsolaNoSePuedeLeerSeUsaElEntorno() {
        var entorno = Map.of("SAM_SIGNER_PASSPHRASE", "frase de ci");
        // Java 22+ da una consola aunque la salida esté redirigida, y leer de ella falla
        java.util.function.Function<String, char[]> rota = p -> {
            throw new java.io.IOError(new java.io.IOException("Controlador no válido"));
        };
        assertThat(SamSigner.prompt(rota, entorno, "Passphrase: ")).containsExactly("frase de ci".toCharArray());
        assertThat(SamSigner.prompt(null, entorno, "Passphrase: ")).containsExactly("frase de ci".toCharArray());
        assertThat(SamSigner.prompt(p -> "de la consola".toCharArray(), entorno, "Passphrase: ")).containsExactly("de la consola".toCharArray());
        assertThat(SamSigner.prompt(rota, Map.of(), "Passphrase: ")).isNull();
    }

    @Test
    void leerUnaCarpetaDaLasRutasConBarraNormal() throws Exception {
        var carpeta = script("leer", "x");
        assertThat(SamSigner.readFolder(carpeta)).containsOnlyKeys("manifest.json", "main.lua", "ui/panel.lua");
        assertThat(List.of(SamSigner.readFolder(carpeta).get("main.lua"))).containsExactly("x".getBytes(StandardCharsets.UTF_8));
    }
}
