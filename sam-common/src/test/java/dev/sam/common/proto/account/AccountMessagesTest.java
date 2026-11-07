package dev.sam.common.proto.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * Los mensajes de la GUI de cuenta y de OAuth (PROTOCOLO.md 5.4 y 5.7) van y vuelven por el codec
 * estricto con sus límites. Lo mal formado que llega es SAM-P001.
 */
class AccountMessagesTest {

    static byte[] escribir(Consumer<SamWriter> mensaje) {
        var buf = Unpooled.buffer();
        mensaje.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    static <T> T leer(byte[] bytes, int max, Function<SamReader, T> mensaje) {
        return SamReader.decode(Unpooled.wrappedBuffer(bytes), max, mensaje);
    }

    static byte[] k(int valor) {
        var k = new byte[32];
        Arrays.fill(k, (byte) valor);
        return k;
    }

    private static void malFormado(Consumer<SamWriter> bytes, Function<SamReader, ?> mensaje, String detalle) {
        assertThatThrownBy(() -> leer(escribir(bytes), 1 << 20, mensaje))
            .isInstanceOfSatisfying(ProtocolException.class, e -> assertThat(e.code()).isEqualTo("SAM-P001"))
            .hasMessage(detalle);
    }

    @Test
    void laInfoDeCuentaVaYVuelve() {
        for (var info : List.of(new AccountInfo("s***@e***.com", true, AccountInfo.Google.LINKED, AccountInfo.Totp.ON),
                new AccountInfo("", false, AccountInfo.Google.UNAVAILABLE, AccountInfo.Totp.UNAVAILABLE),
                new AccountInfo("a".repeat(254), false, AccountInfo.Google.AVAILABLE, AccountInfo.Totp.OFF))) {
            assertThat(leer(escribir(info::write), 512, AccountInfo::read)).isEqualTo(info);
        }
        malFormado(w -> w.string("a".repeat(255), 255), AccountInfo::read, "largo 255 fuera de 0..254");
        malFormado(w -> w.string("x", 254).bool(true).varInt(3), AccountInfo::read, "valor 3 fuera de rango para Google");
        malFormado(w -> w.string("x", 254).bool(true).varInt(0).varInt(3), AccountInfo::read, "valor 3 fuera de rango para Totp");
    }

    @Test
    void elCambioDeCorreoLlevaKYElCorreoNuevo() {
        var cambio = new AccountEmail(k(4), "nuevo@example.com");
        var bytes = escribir(cambio::write);
        assertThat(Arrays.copyOfRange(bytes, 0, 32)).isEqualTo(k(4));
        assertThat(leer(bytes, AccountEmail.MAX_BYTES, AccountEmail::read)).usingRecursiveComparison().isEqualTo(cambio);
        malFormado(w -> w.fixed(k(1), 32).string("a".repeat(255), 255), AccountEmail::read, "largo 255 fuera de 0..254");
        malFormado(w -> w.fixed(new byte[31], 31), AccountEmail::read, "mensaje incompleto");
        assertThatThrownBy(() -> new AccountEmail(new byte[31], "a@b.c")).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("k debe tener 32 bytes");
    }

    @Test
    void desvincularLlevaKYElProveedor() {
        var desvincular = new AccountUnlink(k(5), OAuthProvider.GOOGLE);
        assertThat(leer(escribir(desvincular::write), AccountUnlink.MAX_BYTES, AccountUnlink::read)).usingRecursiveComparison()
            .isEqualTo(desvincular);
        assertThat(escribir(desvincular::write)).hasSize(33);
        malFormado(w -> w.fixed(k(1), 32).varInt(2), AccountUnlink::read, "valor 2 fuera de rango para OAuthProvider");
        assertThatThrownBy(() -> new AccountUnlink(new byte[0], OAuthProvider.GOOGLE)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("k debe tener 32 bytes");
    }

    @Test
    void elResultadoDeCuentaVaYVuelve() {
        for (var resultado : List.of(new AccountResult(AccountResult.Status.OK, Optional.empty()),
                new AccountResult(AccountResult.Status.FAILED, Optional.of("d".repeat(128))),
                new AccountResult(AccountResult.Status.LOCKED, Optional.of("Demasiados intentos")))) {
            assertThat(leer(escribir(resultado::write), 512, AccountResult::read)).isEqualTo(resultado);
        }
        malFormado(w -> w.enumValue(AccountResult.Status.FAILED).optional(Optional.of("d".repeat(129)), (x, d) -> x.string(d, 129)),
            AccountResult::read, "largo 129 fuera de 0..128");
        malFormado(w -> w.varInt(3), AccountResult::read, "valor 3 fuera de rango para Status");
    }

    @Test
    void oauthStartLlevaElProveedorYUnPuertoValido() {
        for (var puerto : List.of(1, 53682, 65535)) {
            var inicio = new OAuthStart(OAuthProvider.DISCORD, puerto);
            assertThat(leer(escribir(inicio::write), OAuthStart.MAX_BYTES, OAuthStart::read)).isEqualTo(inicio);
        }
        malFormado(w -> w.enumValue(OAuthProvider.GOOGLE).varInt(0), OAuthStart::read, "puerto 0 fuera de 1..65535");
        malFormado(w -> w.enumValue(OAuthProvider.GOOGLE).varInt(65536), OAuthStart::read, "puerto 65536 fuera de 1..65535");
        assertThatThrownBy(() -> new OAuthStart(OAuthProvider.GOOGLE, -1)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("puerto -1 fuera de 1..65535");
    }

    @Test
    void laUrlDeOAuthEsHttpsYCorta() {
        var url = new OAuthUrl("https://accounts.google.com/o/oauth2/v2/auth?state=x");
        assertThat(leer(escribir(url::write), 4096, OAuthUrl::read)).isEqualTo(url);
        var larga = "https://a/" + "x".repeat(2048 - 10);
        assertThat(leer(escribir(new OAuthUrl(larga)::write), 4096, OAuthUrl::read).url()).hasSize(2048);
        malFormado(w -> w.string("http://accounts.google.com/", 2048), OAuthUrl::read, "la URL de OAuth debe ser https");
        malFormado(w -> w.string("file:///c:/x", 2048), OAuthUrl::read, "la URL de OAuth debe ser https");
        malFormado(w -> w.string("https://" + "x".repeat(2041), 2049), OAuthUrl::read, "largo 2049 fuera de 0..2048");
    }

    @Test
    void elCodigoDeOAuthLlevaCodigoYState() {
        var codigo = new OAuthCode("4/0AbC-dEf_123", "c3RhdGU");
        assertThat(leer(escribir(codigo::write), OAuthCode.MAX_BYTES, OAuthCode::read)).isEqualTo(codigo);
        var limite = new OAuthCode("c".repeat(1024), "s".repeat(128));
        assertThat(leer(escribir(limite::write), OAuthCode.MAX_BYTES, OAuthCode::read)).isEqualTo(limite);
        malFormado(w -> w.string("c".repeat(1025), 1025), OAuthCode::read, "largo 1025 fuera de 0..1024");
        malFormado(w -> w.string("c", 1024).string("s".repeat(129), 129), OAuthCode::read, "largo 129 fuera de 0..128");
    }
}
