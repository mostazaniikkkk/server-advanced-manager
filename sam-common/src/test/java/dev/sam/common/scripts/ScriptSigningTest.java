package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import dev.sam.common.crypto.Ed25519PrivateKey;
import dev.sam.common.scripts.ScriptVerifier.Reason;
import dev.sam.common.scripts.ScriptVerifier.Result;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

/**
 * RS-SIG-01 / PROTOCOLO.md 8.2: firmar un script (sam-signer) y verificarlo contra las claves de
 * confianza (servidor al cargar, cliente en cada carga).
 */
class ScriptSigningTest {

    private static final Ed25519PrivateKey K1 = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    private static final Ed25519PrivateKey K2 = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    private static final SigningPublicKey PUB_1 = SigningPublicKey.of(K1.publicKeyRaw());
    private static final SigningPublicKey PUB_2 = SigningPublicKey.of(K2.publicKeyRaw());
    private static final String LOCK_SHA = "e0f67bcd51d697c24ce1826b3b5495f0c62b6e877493ee353005854f7a72f38d";

    // ===== Firmar =====

    @Test
    void firmarReproduceElSignatureJsonDeReferencia() {
        // Ed25519 es determinista: la firma Java debe ser idéntica a la de la referencia en Python
        assertThat(new String(ScriptSigner.sign(archivos(), K1), StandardCharsets.UTF_8))
            .isEqualTo(ScriptSignatureTest.VECTOR);
    }

    @Test
    void firmarIgnoraUnSignatureJsonViejo() {
        var conFirmaVieja = archivos();
        conFirmaVieja.put("signature.json", "basura".getBytes(StandardCharsets.UTF_8));
        assertThat(ScriptSigner.sign(conFirmaVieja, K1)).isEqualTo(ScriptSigner.sign(archivos(), K1));
    }

    // ===== Verificar =====

    @Test
    void unScriptFirmadoConUnaClaveDeConfianzaEsValido() {
        assertThat(ScriptVerifier.verify(firmado(K1), List.of(PUB_2, PUB_1)))
            .isEqualTo(new Result.Valid(PUB_1.keyId(), LOCK_SHA));
    }

    @Test
    void sinSignatureJsonSeRechaza() {
        assertThat(ScriptVerifier.verify(archivos(), List.of(PUB_1))).isEqualTo(new Result.Invalid(Reason.MISSING_SIGNATURE));
    }

    @Test
    void unSignatureJsonMalFormadoSeRechaza() {
        var archivos = archivos();
        archivos.put("signature.json", "{}".getBytes(StandardCharsets.UTF_8));
        assertThat(ScriptVerifier.verify(archivos, List.of(PUB_1))).isEqualTo(new Result.Invalid(Reason.MALFORMED_SIGNATURE));
    }

    @Test
    void unaClaveQueNoEsDeConfianzaSeRechaza() {
        assertThat(ScriptVerifier.verify(firmado(K1), List.of(PUB_2))).isEqualTo(new Result.Invalid(Reason.UNKNOWN_KEY));
        assertThat(ScriptVerifier.verify(firmado(K1), List.of())).isEqualTo(new Result.Invalid(Reason.UNKNOWN_KEY));
    }

    @Test
    void modificarUnArchivoInvalidaLaFirma() {
        var archivos = firmado(K1);
        archivos.put("main.lua", "os.execute('rm -rf /')\n".getBytes(StandardCharsets.UTF_8));
        assertThat(ScriptVerifier.verify(archivos, List.of(PUB_1))).isEqualTo(new Result.Invalid(Reason.LOCK_MISMATCH));
    }

    @Test
    void agregarUnArchivoInvalidaLaFirma() {
        var archivos = firmado(K1);
        archivos.put("extra.lua", "print(1)\n".getBytes(StandardCharsets.UTF_8));
        assertThat(ScriptVerifier.verify(archivos, List.of(PUB_1))).isEqualTo(new Result.Invalid(Reason.LOCK_MISMATCH));
    }

    @Test
    void quitarUnArchivoInvalidaLaFirma() {
        var archivos = firmado(K1);
        archivos.remove("ui/panel.lua");
        assertThat(ScriptVerifier.verify(archivos, List.of(PUB_1))).isEqualTo(new Result.Invalid(Reason.LOCK_MISMATCH));
    }

    @Test
    void unaFirmaDeOtraClaveConElKeyIdDeUnaDeConfianzaSeRechaza() {
        // El atacante pone el key_id de K1, pero firma con su propia K2
        var falsa = new ScriptSignature(PUB_1.keyId(), HexFormat.of().parseHex(LOCK_SHA),
            K2.sign(ScriptSigner.signedMessage(HexFormat.of().parseHex(LOCK_SHA))));
        var archivos = archivos();
        archivos.put("signature.json", falsa.toJson());
        assertThat(ScriptVerifier.verify(archivos, List.of(PUB_1))).isEqualTo(new Result.Invalid(Reason.BAD_SIGNATURE));
    }

    @Test
    void archivosConRutasInvalidasSeRechazan() {
        var archivos = firmado(K1);
        archivos.put("../fuera.lua", new byte[0]);
        assertThat(ScriptVerifier.verify(archivos, List.of(PUB_1))).isEqualTo(new Result.Invalid(Reason.INVALID_FILES));
    }

    @Test
    void elMensajeFirmadoLlevaLaEtiquetaDeDominio() {
        var lock = HexFormat.of().parseHex(LOCK_SHA);
        var mensaje = ScriptSigner.signedMessage(lock);
        assertThat(new String(mensaje, 0, 13, StandardCharsets.US_ASCII)).isEqualTo("SAM-script-v1");
        assertThat(java.util.Arrays.copyOfRange(mensaje, 13, mensaje.length)).isEqualTo(lock);
    }

    @Property(tries = 100)
    void cualquierScriptFirmadoSeVerifica(@ForAll @Size(32) byte[] semilla, @ForAll @Size(max = 64) byte[] contenido) {
        var clave = Ed25519PrivateKey.fromSeed(semilla);
        var archivos = new LinkedHashMap<String, byte[]>();
        archivos.put("main.lua", contenido);
        archivos.put("signature.json", ScriptSigner.sign(archivos, clave));
        assertThat(ScriptVerifier.verify(archivos, List.of(SigningPublicKey.of(clave.publicKeyRaw()))))
            .isInstanceOf(Result.Valid.class);
    }

    private static Map<String, byte[]> firmado(Ed25519PrivateKey clave) {
        var archivos = archivos();
        archivos.put("signature.json", ScriptSigner.sign(archivos, clave));
        return archivos;
    }

    /** Los archivos del vector del ciclo 8 (sin el signature.json de la raíz). */
    private static Map<String, byte[]> archivos() {
        var archivos = new LinkedHashMap<String, byte[]>();
        archivos.put("manifest.json", "{\"id\":\"demo\",\"version\":\"1.0.0\"}\n".getBytes(StandardCharsets.UTF_8));
        archivos.put("main.lua", "print(\"hola\")\n".getBytes(StandardCharsets.UTF_8));
        archivos.put("ui/panel.lua", "return {}\n".getBytes(StandardCharsets.UTF_8));
        var png = new byte[16];
        for (int i = 0; i < 16; i++) {
            png[i] = (byte) i;
        }
        archivos.put("assets/icono.png", png);
        archivos.put("sub/signature.json", "incluido".getBytes(StandardCharsets.UTF_8));
        return archivos;
    }
}
