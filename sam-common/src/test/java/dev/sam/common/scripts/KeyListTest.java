package dev.sam.common.scripts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.sam.common.crypto.Ed25519PrivateKey;
import dev.sam.common.identity.ServerPublicKey;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * La lista de claves de firma autorizadas, firmada por la identidad del servidor (PROTOCOLO.md 8.1,
 * RS-SIG-05): el cliente solo confía en las claves que su servidor fijado firmó en esta lista.
 */
class KeyListTest {

    private static KeyPair identidad;
    private static KeyPair otraIdentidad;
    private static final SigningPublicKey STEVE = SigningPublicKey.of(Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).publicKeyRaw());
    private static final SigningPublicKey ALEX = SigningPublicKey.of(Ed25519PrivateKey.fromSeed(
        HexFormat.of().parseHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")).publicKeyRaw());

    @BeforeAll
    static void identidades() throws Exception {
        identidad = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        otraIdentidad = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static ServerPublicKey publica(KeyPair par) {
        return ServerPublicKey.fromSpki(par.getPublic().getEncoded());
    }

    private static byte[] escribir(SignedBlob blob) {
        var buf = Unpooled.buffer();
        blob.write(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    private static List<KeyList.Entry> lista() {
        return List.of(new KeyList.Entry(STEVE, "steve"), new KeyList.Entry(ALEX, "alex"));
    }

    @Test
    void laListaFirmadaSeVerificaConLaIdentidadDelServidor() {
        var blob = KeyList.issue(lista(), identidad.getPrivate(), 1_762_500_000L);
        assertThat(blob.type()).isEqualTo("keylist");
        assertThat(blob.issuedAt()).isEqualTo(1_762_500_000L);
        assertThat(KeyList.verify(blob, publica(identidad))).contains(lista());
        assertThat(KeyList.verify(blob, publica(otraIdentidad))).as("otro servidor").isEmpty();
        // Va y vuelve por el codec estricto
        var leido = SamReader.decode(Unpooled.wrappedBuffer(escribir(blob)), 1 << 20, SignedBlob::read);
        assertThat(KeyList.verify(leido, publica(identidad))).contains(lista());
    }

    @Test
    void cualquierCambioInvalidaLaFirma() {
        var blob = KeyList.issue(lista(), identidad.getPrivate(), 100L);
        var cuerpo = blob.body();
        cuerpo[cuerpo.length - 1] ^= 1;
        var casos = List.of(
            new SignedBlob("keylis", blob.version(), blob.issuedAt(), blob.body(), blob.signature()),
            new SignedBlob(blob.type(), blob.version() + 1, blob.issuedAt(), blob.body(), blob.signature()),
            new SignedBlob(blob.type(), blob.version(), blob.issuedAt() + 1, blob.body(), blob.signature()),
            new SignedBlob(blob.type(), blob.version(), blob.issuedAt(), cuerpo, blob.signature()));
        for (var caso : casos) {
            assertThat(caso.verify(publica(identidad))).as(caso.toString()).isFalse();
        }
        assertThat(blob.verify(publica(identidad))).isTrue();
    }

    @Test
    void unaListaDeOtroTipoONoDecodificableSeRechaza() {
        var otro = SignedBlob.sign("rotation", 1, 5L, new byte[] {0}, identidad.getPrivate());
        assertThat(KeyList.verify(otro, publica(identidad))).isEmpty();
        var basura = SignedBlob.sign("keylist", 1, 5L, new byte[] {7, 7, 7}, identidad.getPrivate());
        assertThat(KeyList.verify(basura, publica(identidad))).isEmpty();
    }

    @Test
    void unKeyIdQueNoCorrespondeALaClaveSeRechaza() {
        var buf = Unpooled.buffer();
        new SamWriter(buf).list(List.of(STEVE), 64, (w, k) -> w.fixed(HexFormat.of().parseHex(ALEX.keyId().hex()), 8).fixed(k.raw(), 32).string("steve", 64));
        var blob = SignedBlob.sign("keylist", 1, 5L, ByteBufUtil.getBytes(buf), identidad.getPrivate());
        assertThat(KeyList.verify(blob, publica(identidad))).isEmpty();
    }

    @Test
    void losLimitesSeExigen() {
        assertThatThrownBy(() -> new SignedBlob("t", 1, 0, new byte[64 * 1024 + 1], new byte[64]))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("body supera 64 KiB");
        assertThatThrownBy(() -> new SignedBlob("t", 1, 0, new byte[0], new byte[63]))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("la firma debe medir 64 bytes");
        assertThat(new SignedBlob("t", 1, 0, new byte[64 * 1024], new byte[64]).body()).hasSize(64 * 1024);
        var muchas = new java.util.ArrayList<KeyList.Entry>();
        for (var i = 0; i < 65; i++) {
            muchas.add(new KeyList.Entry(STEVE, "k" + i));
        }
        assertThatThrownBy(() -> KeyList.issue(muchas, identidad.getPrivate(), 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SamReader.decode(Unpooled.wrappedBuffer(new byte[] {1, 't'}), 1 << 20, SignedBlob::read))
            .isInstanceOf(ProtocolException.class);
        // Los arreglos se copian
        var blob = KeyList.issue(lista(), identidad.getPrivate(), 1L);
        blob.body()[0] = 99;
        blob.signature()[0] = 99;
        assertThat(blob.verify(publica(identidad))).isTrue();
        assertThat(Arrays.equals(blob.body(), blob.body())).isTrue();
    }

    @Test
    void laFirmaCoincideConLaImplementacionDeReferencia() throws Exception {
        // Vector calculado con la librería cryptography de Python (Ed25519 es determinista)
        var pkcs8 = HexFormat.of().parseHex("302e020100300506032b657004220420"
            + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var clave = java.security.KeyFactory.getInstance("Ed25519").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
        var blob = SignedBlob.sign("keylist", 1, 1_762_500_000L, new byte[] {1, 2, 3}, clave);
        assertThat(HexFormat.of().formatHex(blob.signature())).isEqualTo("3c2f84731acf08bb123ba97adce8db67a8cd797f3e4f2136bd66b5008660899d"
            + "9ea955c65d5f1b168b7226036b34a7d2914d34c20d8b0179d5af1f46f2a53104");
    }
}
