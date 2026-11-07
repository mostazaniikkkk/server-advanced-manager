package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.FileSystem;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import dev.sam.common.crypto.Ed25519PrivateKey;

/**
 * El trust store de scripts (RS-SIG-02/03/06): las claves públicas en {@code keys/trusted/*.pub}; una
 * clave nueva queda pendiente hasta que un admin la confirma desde la consola; quitar el archivo la
 * revoca.
 */
class TrustStoreTest {

    private static final Ed25519PrivateKey K1 = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    private static final Ed25519PrivateKey K2 = Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    private static final SigningPublicKey PUB1 = SigningPublicKey.of(K1.publicKeyRaw());
    private static final SigningPublicKey PUB2 = SigningPublicKey.of(K2.publicKeyRaw());

    private FileSystem fs;
    private java.nio.file.Path keys;

    @BeforeEach
    void disco() throws Exception {
        fs = Jimfs.newFileSystem(Configuration.unix());
        keys = fs.getPath("/server/config/sam/keys");
        Files.createDirectories(keys.resolve("trusted"));
    }

    private void clave(String nombre, Ed25519PrivateKey k) throws Exception {
        Files.writeString(keys.resolve("trusted").resolve(nombre),
            "# clave de Steve\n" + Base64.getEncoder().encodeToString(k.publicKeyRaw()) + "\n");
    }

    @Test
    void unaClaveNuevaQuedaPendienteHastaConfirmarla() throws Exception {
        clave("steve.pub", K1);
        var store = TrustStore.load(keys);
        assertThat(store.active()).isEmpty();
        assertThat(store.pending()).containsExactly(new TrustStore.Pending(PUB1.keyId(), "steve.pub"));
        assertThat(TrustStore.confirm(keys, PUB1.keyId())).isTrue();
        var confirmado = TrustStore.load(keys);
        assertThat(confirmado.active()).containsExactly(PUB1);
        assertThat(confirmado.pending()).isEmpty();
        assertThat(Files.readString(keys.resolve("confirmed.txt"))).isEqualTo(PUB1.keyId().hex() + "\n");
        // Confirmar dos veces no la repite; confirmar algo que no está pendiente no hace nada
        assertThat(TrustStore.confirm(keys, PUB1.keyId())).isFalse();
        assertThat(TrustStore.confirm(keys, PUB2.keyId())).isFalse();
        assertThat(Files.readString(keys.resolve("confirmed.txt"))).isEqualTo(PUB1.keyId().hex() + "\n");
    }

    @Test
    void soloSeConfirmaLaClavePendienteQueSeNombra() throws Exception {
        // Con una pendiente (K2), confirmar otra que no está (K1) no hace nada
        Files.writeString(keys.resolve("trusted").resolve("alex.pub"), "\n\n" + Base64.getEncoder().encodeToString(K2.publicKeyRaw()));
        assertThat(TrustStore.load(keys).pending()).extracting(TrustStore.Pending::keyId).containsExactly(PUB2.keyId());
        assertThat(TrustStore.confirm(keys, PUB1.keyId())).isFalse();
        assertThat(Files.exists(keys.resolve("confirmed.txt"))).isFalse();
    }

    @Test
    void quitarElArchivoRevocaLaClave() throws Exception {
        clave("steve.pub", K1);
        clave("alex.pub", K2);
        TrustStore.confirm(keys, PUB1.keyId());
        TrustStore.confirm(keys, PUB2.keyId());
        assertThat(TrustStore.load(keys).active()).containsExactlyInAnyOrder(PUB1, PUB2);
        Files.delete(keys.resolve("trusted").resolve("alex.pub"));
        assertThat(TrustStore.load(keys).active()).containsExactly(PUB1);
    }

    @Test
    void losArchivosMalosSeInformanSinRomperLoDemas() throws Exception {
        clave("bien.pub", K1);
        TrustStore.confirm(keys, PUB1.keyId());
        Files.writeString(keys.resolve("trusted").resolve("mal.pub"), "no es base64!");
        Files.writeString(keys.resolve("trusted").resolve("corta.pub"), Base64.getEncoder().encodeToString(new byte[31]));
        Files.writeString(keys.resolve("trusted").resolve("notas.txt"), "se ignora");
        var store = TrustStore.load(keys);
        assertThat(store.active()).containsExactly(PUB1);
        assertThat(store.problems()).containsExactlyInAnyOrder("corta.pub: no es una clave pública Ed25519 en base64",
            "mal.pub: no es una clave pública Ed25519 en base64");
    }

    @Test
    void sinCarpetaNoHayClaves() throws Exception {
        var vacio = fs.getPath("/otro");
        var store = TrustStore.load(vacio);
        assertThat(store.active()).isEmpty();
        assertThat(store.pending()).isEmpty();
        assertThat(store.problems()).isEmpty();
        // Una línea basura en confirmed.txt se ignora (solo valen key_id de claves presentes)
        clave("steve.pub", K1);
        Files.writeString(keys.resolve("confirmed.txt"), "basura\n\n" + PUB1.keyId().hex() + "\n");
        assertThat(TrustStore.load(keys).active()).containsExactly(PUB1);
    }

    @Test
    void lasClavesActivasLlevanElNombreDeSuArchivo() throws Exception {
        clave("steve.pub", K1);
        var largo = "ñ".repeat(40) + ".pub";
        clave(largo, K2);
        TrustStore.confirm(keys, PUB1.keyId());
        TrustStore.confirm(keys, PUB2.keyId());
        var store = TrustStore.load(keys);
        assertThat(store.entries()).extracting(KeyList.Entry::key).containsExactlyInAnyOrder(PUB1, PUB2);
        assertThat(store.entries()).filteredOn(e -> e.key().equals(PUB1)).singleElement()
            .satisfies(e -> assertThat(e.label()).isEqualTo("steve"));
        // La etiqueta cabe en la keylist (64 bytes en UTF-8) sin cortar un carácter
        assertThat(store.entries()).filteredOn(e -> e.key().equals(PUB2)).singleElement()
            .satisfies(e -> assertThat(e.label()).isEqualTo("ñ".repeat(32)));
    }
}
