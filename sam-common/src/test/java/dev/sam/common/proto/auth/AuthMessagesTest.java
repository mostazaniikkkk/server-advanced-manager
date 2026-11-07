package dev.sam.common.proto.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerId;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/**
 * Los mensajes del login (PROTOCOLO.md 5.1 y 5.3) van y vuelven por el codec estricto, con sus
 * límites. Lo que llega mal formado del otro lado es SAM-P001; lo que se intenta escribir fuera de
 * límite es un error de programación.
 */
class AuthMessagesTest {

    private static final ServerId ID = ServerId.fromHex("45f6c09d17e093f73d707e48bed9de34");
    private static final AuthPolicyView POLITICA = new AuthPolicyView(List.of(AuthMethod.PASSWORD, AuthMethod.PASSWORD_TOTP),
        false, false, EmailVerify.LATER, 10);

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
    void elHelloVaYVuelve() {
        var hello = new Hello(ProtocolVersion.CURRENT, ID, "Mi Servidor ñ", List.of("oauth.google", "lua.gui"),
            AccountState.REGISTERED, POLITICA);
        var leido = leer(escribir(hello::write), 1 << 18, Hello::read);
        assertThat(leido).usingRecursiveComparison().isEqualTo(hello);
        assertThat(leido.serverId()).isEqualTo(ID);
        var sinNada = new Hello(new ProtocolVersion(255, 255), ID, "", List.of(), AccountState.NEW,
            new AuthPolicyView(List.of(), true, true, EmailVerify.BEFORE_PLAY, 0));
        assertThat(leer(escribir(sinNada::write), 1 << 18, Hello::read)).usingRecursiveComparison().isEqualTo(sinNada);
    }

    @Test
    void elHelloEmpiezaPorLaVersionYElServerId() {
        var bytes = escribir(new Hello(ProtocolVersion.CURRENT, ID, "S", List.of(), AccountState.NEW, POLITICA)::write);
        assertThat(Arrays.copyOfRange(bytes, 0, 2)).containsExactly(1, 0);
        assertThat(Arrays.copyOfRange(bytes, 2, 18)).isEqualTo(ID.toBytes());
    }

    @Test
    void losLimitesDelHelloSeExigenAlLeer() {
        malFormado(w -> w.varInt(256).varInt(0), Hello::read, "versión 256.0 fuera de rango");
        malFormado(w -> w.varInt(1).varInt(-1), Hello::read, "versión 1.-1 fuera de rango");
        malFormado(w -> w.varInt(1).varInt(256), Hello::read, "versión 1.256 fuera de rango");
        malFormado(w -> w.varInt(-1).varInt(0), Hello::read, "versión -1.0 fuera de rango");
        malFormado(w -> {
            ProtocolVersion.CURRENT.write(w);
            w.fixed(ID.toBytes(), 16).string("x".repeat(65), 65);
        }, Hello::read, "largo 65 fuera de 0..64");
        malFormado(w -> base(w).list(Collections.nCopies(33, "f"), 33, (x, f) -> x.string(f, 32)), Hello::read,
            "largo 33 fuera de 0..32");
        malFormado(w -> base(w).list(List.of("f".repeat(33)), 32, (x, f) -> x.string(f, 33)), Hello::read,
            "largo 33 fuera de 0..32");
        malFormado(w -> base(w).list(List.of(), 32, (x, f) -> { }).varInt(3), Hello::read,
            "valor 3 fuera de rango para AccountState");
    }

    private static SamWriter base(SamWriter w) {
        ProtocolVersion.CURRENT.write(w);
        return w.fixed(ID.toBytes(), 16).string("S", 64);
    }

    @Test
    void losLimitesDeLaPoliticaSeExigenAlLeer() {
        malFormado(w -> w.list(Collections.nCopies(6, AuthMethod.PASSWORD), 6, SamWriter::enumValue), AuthPolicyView::read,
            "largo 6 fuera de 0..5");
        malFormado(w -> w.list(List.of(), 5, SamWriter::enumValue).bool(false).bool(false).enumValue(EmailVerify.LATER).varInt(129),
            AuthPolicyView::read, "min_password 129 fuera de 0..128");
        malFormado(w -> w.list(List.of(), 5, SamWriter::enumValue).bool(false).bool(false).enumValue(EmailVerify.LATER).varInt(-1),
            AuthPolicyView::read, "min_password -1 fuera de 0..128");
        assertThat(leer(escribir(w -> new AuthPolicyView(List.of(AuthMethod.values()), false, false, EmailVerify.LATER, 128)
            .write(w)), 512, AuthPolicyView::read).minPassword()).isEqualTo(128);
    }

    @Test
    void elHelloAckVaYVuelveYRespetaSusLimites() {
        var ack = new HelloAck(ProtocolVersion.CURRENT, "0.1.0", k(7));
        var leido = leer(escribir(ack::write), HelloAck.MAX_BYTES, HelloAck::read);
        assertThat(leido).usingRecursiveComparison().isEqualTo(ack);
        malFormado(w -> {
            ProtocolVersion.CURRENT.write(w);
            w.string("", 32);
        }, HelloAck::read, "mensaje incompleto");
        malFormado(w -> { ProtocolVersion.CURRENT.write(w); w.string("x".repeat(33), 33); }, HelloAck::read, "largo 33 fuera de 0..32");
        malFormado(w -> { ProtocolVersion.CURRENT.write(w); w.string("v", 32).fixed(new byte[31], 31); }, HelloAck::read,
            "mensaje incompleto");
        assertThatThrownBy(() -> new HelloAck(ProtocolVersion.CURRENT, "v", new byte[31])).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("device_pub debe tener 32 bytes");
    }

    @Test
    void elRegistroLlevaKYCorreo() {
        var registro = new Register(k(1), "steve@example.com");
        var bytes = escribir(registro::write);
        assertThat(Arrays.copyOfRange(bytes, 0, 32)).isEqualTo(k(1));
        assertThat(bytes[32]).isEqualTo((byte) 17);
        assertThat(leer(bytes, Register.MAX_BYTES, Register::read)).usingRecursiveComparison().isEqualTo(registro);
        malFormado(w -> w.fixed(k(1), 32).string("a".repeat(255), 255), Register::read, "largo 255 fuera de 0..254");
        assertThat(leer(escribir(w -> w.fixed(k(1), 32).string("a".repeat(254), 254)), Register.MAX_BYTES, Register::read).email())
            .hasSize(254);
        assertThatThrownBy(() -> new Register(new byte[16], "a@b.c")).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("k debe tener 32 bytes");
    }

    @Test
    void elLoginConContrasenaLlevaKYElTotpOpcional() {
        var sinTotp = new LoginPassword(k(2), Optional.empty());
        var conTotp = new LoginPassword(k(3), Optional.of("012345"));
        assertThat(leer(escribir(sinTotp::write), LoginPassword.MAX_BYTES, LoginPassword::read)).usingRecursiveComparison()
            .isEqualTo(sinTotp);
        assertThat(leer(escribir(conTotp::write), LoginPassword.MAX_BYTES, LoginPassword::read)).usingRecursiveComparison()
            .isEqualTo(conTotp);
        assertThat(escribir(sinTotp::write)).hasSize(33);
        for (var malo : List.of("12345", "12a456", "１２３４５６", "")) {
            malFormado(w -> w.fixed(k(1), 32).optional(Optional.of(malo), (x, t) -> x.string(t, 18)), LoginPassword::read,
                malo.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 6
                    ? "largo " + malo.getBytes(java.nio.charset.StandardCharsets.UTF_8).length + " fuera de 0..6"
                    : "el TOTP debe tener 6 dígitos");
        }
        malFormado(w -> w.fixed(k(1), 32).optional(Optional.of("1234567"), (x, t) -> x.string(t, 7)), LoginPassword::read,
            "largo 7 fuera de 0..6");
        assertThatThrownBy(() -> new LoginPassword(k(1), Optional.of("abc"))).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("el TOTP debe tener 6 dígitos");
        assertThatThrownBy(() -> new LoginPassword(new byte[33], Optional.empty())).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("k debe tener 32 bytes");
    }

    @Test
    void elSegundoPasoLlevaElCodigo() {
        for (var codigo : List.of("012345", "abcd-efgh", "x".repeat(16))) {
            var mensaje = new LoginTotp(codigo);
            assertThat(leer(escribir(mensaje::write), LoginTotp.MAX_BYTES, LoginTotp::read)).isEqualTo(mensaje);
        }
        malFormado(w -> w.string("x".repeat(17), 17), LoginTotp::read, "largo 17 fuera de 0..16");
    }

    @Test
    void elResultadoVaYVuelveYSuDetalleEsCorto() {
        for (var resultado : List.of(new AuthResult(AuthResult.Status.OK, Optional.empty(), Optional.empty()),
                new AuthResult(AuthResult.Status.LOCKED, Optional.of(900), Optional.of("Demasiados intentos")))) {
            assertThat(leer(escribir(resultado::write), 512, AuthResult::read)).isEqualTo(resultado);
        }
        assertThat(leer(escribir(new AuthResult(AuthResult.Status.FAILED, Optional.of(0), Optional.of("d".repeat(128)))::write), 512,
            AuthResult::read).retryAfterSeconds()).contains(0);
        malFormado(w -> w.enumValue(AuthResult.Status.FAILED).optional(Optional.of(-1), SamWriter::varInt).bool(false), AuthResult::read,
            "retry_after negativo");
        malFormado(w -> w.enumValue(AuthResult.Status.FAILED).optional(Optional.empty(), SamWriter::varInt)
            .optional(Optional.of("d".repeat(129)), (x, d) -> x.string(d, 129)), AuthResult::read, "largo 129 fuera de 0..128");
        malFormado(w -> w.varInt(8), AuthResult::read, "valor 8 fuera de rango para Status");
    }

    @Test
    void losRegistrosValidanLoQueSeVaAEscribir() {
        assertThatThrownBy(() -> new ProtocolVersion(256, 0)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("versión 256.0 fuera de rango");
        assertThatThrownBy(() -> new ProtocolVersion(0, -1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthPolicyView(List.of(), false, false, EmailVerify.LATER, 129))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("min_password 129 fuera de 0..128");
        assertThatThrownBy(() -> new AuthPolicyView(List.of(), false, false, EmailVerify.LATER, -1))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthResult(AuthResult.Status.OK, Optional.of(-5), Optional.empty()))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("retry_after negativo");
        assertThat(new ProtocolVersion(255, 0).major()).isEqualTo(255);
        assertThat(new ProtocolVersion(0, 255).minor()).isEqualTo(255);
    }
}
