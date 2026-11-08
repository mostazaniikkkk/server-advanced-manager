package dev.sam.common.totp;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.util.Optional;

import org.junit.jupiter.api.Test;

/** RF-CFG-12 (H-13, H-14): campos cifrados con la clave de datos, con id de clave y rotación. */
class FieldCipherTest {

    private static final DataKey A = DataKey.parse(DataKey.suggest(new SecureRandom()));
    private static final DataKey B = DataKey.parse(DataKey.suggest(new SecureRandom()));

    @Test
    void idaYVueltaConElIdDeLaClave() {
        var cifrador = new FieldCipher(new KeyRing(A, Optional.empty()), new SecureRandom());
        var sellado = cifrador.seal("email:steve", "steve@example.com");
        assertThat(sellado).startsWith("enc1:" + A.id() + ":").doesNotContain("steve@example.com");
        assertThat(FieldCipher.isSealed(sellado)).isTrue();
        assertThat(FieldCipher.isSealed("steve@example.com")).isFalse();
        assertThat(cifrador.open("email:steve", sellado)).contains("steve@example.com");
        assertThat(cifrador.seal("email:steve", "x")).isNotEqualTo(cifrador.seal("email:steve", "x"));
    }

    @Test
    void elContextoVaEnLaAutenticacion() {
        var cifrador = new FieldCipher(new KeyRing(A, Optional.empty()), new SecureRandom());
        var sellado = cifrador.seal("email:steve", "steve@example.com");
        assertThat(cifrador.open("email:alex", sellado)).isEmpty();
    }

    @Test
    void conLaClaveAnteriorTodaviaAbreYSellaConLaNueva() {
        var viejo = new FieldCipher(new KeyRing(A, Optional.empty()), new SecureRandom()).seal("google:steve", "sub-1");
        var rotado = new FieldCipher(new KeyRing(B, Optional.of(A)), new SecureRandom());
        assertThat(rotado.open("google:steve", viejo)).contains("sub-1");
        assertThat(rotado.seal("google:steve", "sub-1")).startsWith("enc1:" + B.id() + ":");
        assertThat(rotado.needsRekey(viejo)).isTrue();
        assertThat(rotado.needsRekey(rotado.seal("google:steve", "sub-1"))).isFalse();
        var soloNueva = new FieldCipher(new KeyRing(B, Optional.empty()), new SecureRandom());
        assertThat(soloNueva.open("google:steve", viejo)).isEmpty();
    }

    @Test
    void basuraNoAbre() {
        var cifrador = new FieldCipher(new KeyRing(A, Optional.empty()), new SecureRandom());
        for (var malo : new String[] {"enc1:", "enc1:" + A.id(), "enc1:" + A.id() + ":%%%", "enc1:" + A.id() + ":AAAA",
            "enc1:00000000:" + cifrador.seal("x", "y").substring(14), "texto"}) {
            assertThat(cifrador.open("x", malo)).as(malo).isEmpty();
        }
    }

    @Test
    void elIdEsEstableYDistintoPorClave() {
        assertThat(A.id()).matches("[0-9a-f]{8}").isEqualTo(A.id());
        assertThat(A.id()).isNotEqualTo(B.id());
        assertThat(DataKey.parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").id()).isEqualTo("66687aad");
    }

    @Test
    void elAnilloListaPrimeroLaActual() {
        assertThat(new KeyRing(B, Optional.of(A)).all()).containsExactly(B, A);
        assertThat(new KeyRing(B, Optional.empty()).all()).containsExactly(B);
    }

    @Test
    void elTotpSelladoConLaAnteriorTambienAbre() {
        var estado = new TotpState(new byte[20], java.util.List.of(), 7);
        var viejo = new TotpVault(A, new SecureRandom()).seal("steve", estado);
        var rotado = new TotpVault(new KeyRing(B, Optional.of(A)), new SecureRandom());
        assertThat(rotado.open("steve", viejo)).hasValueSatisfying(s -> assertThat(s.lastStep()).isEqualTo(7));
        assertThat(new TotpVault(B, new SecureRandom()).open("steve", viejo)).isEmpty();
        var nuevo = rotado.seal("steve", estado);
        assertThat(new TotpVault(B, new SecureRandom()).open("steve", nuevo)).isPresent();
    }
}
