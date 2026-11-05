package dev.sam.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import dev.sam.common.identity.ServerId;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.NumericChars;
import net.jqwik.api.constraints.Size;
import net.jqwik.api.constraints.StringLength;

/**
 * RS-AUTH-01 / PROTOCOLO.md 6.1: contraseña ligada al servidor.
 *
 * <p>Los vectores se calcularon con argon2-cffi (libargon2, implementación de referencia en C),
 * independiente de la librería que usa SAM.
 */
class PasswordDerivationTest {

    private static final ServerId SID_1 = ServerId.fromHex("00000000000000000000000000000001");
    private static final ServerId SID_2 = ServerId.fromHex("00000000000000000000000000000002");
    private static final String V_PW_1 = "2670fc91c53990ea43eee76bdd79ab9dc1c573e61eaa334ba76f3d632e453ff0";

    /** Parámetros mínimos para que las propiedades corran rápido. Los vectores usan los reales. */
    private static final Argon2Params FAST = new Argon2Params(64, 1, 1);

    // ===== Salt del cliente =====

    @Test
    void saltDelClienteCoincideConLaReferencia() {
        assertThat(hex(PasswordDerivation.clientSalt(SID_1, "Steve"))).isEqualTo("dbbc407f54f9da1064ac152aa8bfce53");
        assertThat(hex(PasswordDerivation.clientSalt(SID_1, "Alex"))).isEqualTo("4dd1f807568c9881943f3541a17464a2");
    }

    @Property
    void elSaltNoDistingueMayusculasEnElUsuario(@ForAll @AlphaChars @NumericChars @StringLength(min = 3, max = 16) String usuario) {
        assertThat(PasswordDerivation.clientSalt(SID_1, usuario.toUpperCase(java.util.Locale.ROOT)))
            .isEqualTo(PasswordDerivation.clientSalt(SID_1, usuario.toLowerCase(java.util.Locale.ROOT)));
    }

    @Property
    void elSaltCambiaConElServidor(@ForAll @Size(16) byte[] a, @ForAll @Size(16) byte[] b) {
        var idA = ServerId.of(a);
        var idB = ServerId.of(b);
        if (idA.equals(idB)) {
            return;
        }
        assertThat(PasswordDerivation.clientSalt(idA, "Steve")).isNotEqualTo(PasswordDerivation.clientSalt(idB, "Steve"));
    }

    // ===== Vectores con los parámetros reales del protocolo (P-06) =====

    @Test
    void vectorVPW1() {
        assertThat(hex(derive("correct horse battery staple", SID_1, "Steve"))).isEqualTo(V_PW_1);
    }

    @Test
    void vectorVPW2ElUsuarioEnMinusculasDaElMismoK() {
        assertThat(hex(derive("correct horse battery staple", SID_1, "steve"))).isEqualTo(V_PW_1);
    }

    @Test
    void vectorVPW3NfcYNfdDanElMismoK() {
        var esperado = "94714c539adbeaee90659b787bca88a187ae136684ec47c06e7a629b7c4c6c4d";
        assertThat(hex(derive("contraseña", SID_1, "Alex"))).isEqualTo(esperado);
        assertThat(hex(derive("contraseña", SID_1, "Alex"))).isEqualTo(esperado);
    }

    @Test
    void vectorVPW4CaracteresDeAnchoCompletoSeNormalizanConNfkc() {
        var fullwidth = "ｃｏｒｒｅｃｔ horse battery staple";
        assertThat(hex(derive(fullwidth, SID_1, "Steve"))).isEqualTo(V_PW_1);
    }

    @Test
    void vectorVPW5LaMismaContrasenaEnOtroServidorDaOtroK() {
        // El núcleo de RN-09: lo que recibe un servidor falso no sirve en el real
        assertThat(hex(derive("correct horse battery staple", SID_2, "Steve")))
            .isEqualTo("1e84d73bb6c8debda213736336d99b3c756f33ef6a85deb14f96b0b8c783b1ed");
    }

    // ===== Higiene de memoria y validación =====

    @Test
    void borraLaContrasenaDelArregloDeEntrada() {
        var password = "correct horse".toCharArray();
        PasswordDerivation.deriveClientKey(password, SID_1, "Steve", FAST);
        assertThat(password).containsOnly('\0');
    }

    @Test
    void borraLosBytesCodificadosAlTerminar() {
        var capturado = new byte[1][];
        PasswordDerivation.withNfkcUtf8("secreto".toCharArray(), bytes -> {
            assertThat(new String(bytes, java.nio.charset.StandardCharsets.UTF_8)).isEqualTo("secreto");
            capturado[0] = bytes;
            return null;
        });
        assertThat(capturado[0]).containsOnly((byte) 0);
    }

    @Test
    void borraTodoAunqueLaAccionFalle() {
        var password = "secreto".toCharArray();
        var capturado = new byte[1][];
        assertThatThrownBy(() -> PasswordDerivation.withNfkcUtf8(password, bytes -> {
            capturado[0] = bytes;
            throw new IllegalStateException("falla simulada");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(password).containsOnly('\0');
        assertThat(capturado[0]).containsOnly((byte) 0);
    }

    @Test
    void borraLaContrasenaAunqueElUsuarioSeaInvalido() {
        var password = "secreto".toCharArray();
        assertThatThrownBy(() -> PasswordDerivation.deriveClientKey(password, SID_1, " ", FAST))
            .isInstanceOf(IllegalArgumentException.class);
        assertThat(password).containsOnly('\0');
    }

    @Test
    void elResultadoMide32Bytes() {
        assertThat(PasswordDerivation.deriveClientKey("x".toCharArray(), SID_1, "Steve", FAST)).hasSize(32);
    }

    @Test
    void rechazaUnaContrasenaVacia() {
        assertThatThrownBy(() -> PasswordDerivation.deriveClientKey(new char[0], SID_1, "Steve", FAST))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "   "})
    void rechazaUnUsuarioVacio(String usuario) {
        assertThatThrownBy(() -> PasswordDerivation.clientSalt(SID_1, usuario))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Property(tries = 50)
    void contrasenasDistintasDanKDistintos(
            @ForAll @StringLength(min = 1, max = 32) String a, @ForAll @StringLength(min = 1, max = 32) String b) {
        if (java.text.Normalizer.normalize(a, java.text.Normalizer.Form.NFKC)
                .equals(java.text.Normalizer.normalize(b, java.text.Normalizer.Form.NFKC))) {
            return;
        }
        assertThat(PasswordDerivation.deriveClientKey(a.toCharArray(), SID_1, "Steve", FAST))
            .isNotEqualTo(PasswordDerivation.deriveClientKey(b.toCharArray(), SID_1, "Steve", FAST));
    }

    private static byte[] derive(String password, ServerId serverId, String usuario) {
        return PasswordDerivation.deriveClientKey(password.toCharArray(), serverId, usuario);
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
