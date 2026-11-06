package dev.sam.common.auth;

import static dev.sam.common.auth.AccountServiceTest.k;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerId;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.auth.AccountState;
import dev.sam.common.proto.auth.AuthMethod;
import dev.sam.common.proto.auth.AuthPolicyView;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.AuthResult.Status;
import dev.sam.common.proto.auth.EmailVerify;
import dev.sam.common.proto.auth.HelloAck;
import dev.sam.common.proto.auth.LoginPassword;
import dev.sam.common.proto.auth.ProtocolVersion;
import dev.sam.common.proto.auth.Register;

/** El login de una conexión (PROTOCOLO.md 4.4 y 5): estados, intentos y expulsiones. */
class LoginFlowTest {

    private static final ServerId ID = ServerId.fromHex("45f6c09d17e093f73d707e48bed9de34");
    private static final AuthPolicyView POLITICA = new AuthPolicyView(List.of(AuthMethod.PASSWORD), false, false,
        EmailVerify.LATER, 10);
    private static final HelloAck ACK = new HelloAck(ProtocolVersion.CURRENT, "0.1.0", new byte[32]);

    private final AccountService cuentas = new AccountService(List.of(), new Argon2Params(8, 1, 1), new SecureRandom(), c -> { });

    private LoginFlow flujo(String nick) {
        return new LoginFlow(nick, ID, "Mi Servidor", POLITICA, cuentas, 3);
    }

    private static LoginFlow.Reply nada() {
        return new LoginFlow.Reply(Optional.empty(), Optional.empty(), false);
    }

    private static void fueraDeEstado(Runnable mensaje) {
        assertThatThrownBy(mensaje::run)
            .isInstanceOfSatisfying(ProtocolException.class, e -> assertThat(e.code()).isEqualTo("SAM-P002"));
    }

    @Test
    void elHelloPresentaAlServidorYElEstadoDelNick() {
        cuentas.register("Steve", k(1), "s@e.com");
        var hello = flujo("STEVE").hello();
        assertThat(hello).isNotNull();
        assertThat(hello.protocol()).isEqualTo(ProtocolVersion.CURRENT);
        assertThat(hello.serverId()).isEqualTo(ID);
        assertThat(hello.serverName()).isEqualTo("Mi Servidor");
        assertThat(hello.features()).isEmpty();
        assertThat(hello.accountState()).isEqualTo(AccountState.REGISTERED);
        assertThat(hello.policy()).isEqualTo(POLITICA);
        assertThat(flujo("Alex").hello().accountState()).isEqualTo(AccountState.NEW);
    }

    @Test
    void unJugadorNuevoSeRegistraYTermina() {
        var flujo = flujo("Steve");
        flujo.hello();
        assertThat(flujo.onHelloAck(ACK)).isEqualTo(nada());
        var respuesta = flujo.onRegister(new Register(k(1), "steve@example.com"));
        assertThat(respuesta.result()).hasValueSatisfying(r -> assertThat(r.status()).isEqualTo(Status.OK));
        assertThat(respuesta.kick()).isEmpty();
        assertThat(respuesta.done()).isTrue();
        assertThat(flujo.done()).isTrue();
        assertThat(cuentas.state("steve")).isEqualTo(AccountState.REGISTERED);
    }

    @Test
    void unJugadorRegistradoEntraConSuContrasena() {
        cuentas.register("Steve", k(1), "s@e.com");
        var flujo = flujo("Steve");
        flujo.hello();
        flujo.onHelloAck(ACK);
        var mal = flujo.onLogin(new LoginPassword(k(2), Optional.empty()));
        assertThat(mal).isEqualTo(new LoginFlow.Reply(Optional.of(new AuthResult(Status.FAILED, Optional.empty(),
            Optional.of(AccountService.LOGIN_FAILED))), Optional.empty(), false));
        assertThat(flujo.done()).isFalse();
        var bien = flujo.onLogin(new LoginPassword(k(1), Optional.empty()));
        assertThat(bien.done()).isTrue();
        assertThat(bien.result()).hasValueSatisfying(r -> assertThat(r.status()).isEqualTo(Status.OK));
    }

    @Test
    void elRegistroUsaElNickDeLaConexionNoOtro() {
        var flujo = flujo("Steve");
        flujo.hello();
        flujo.onHelloAck(ACK);
        flujo.onRegister(new Register(k(1), "s@e.com"));
        assertThat(cuentas.login("Steve", k(1)).status()).isEqualTo(Status.OK);
        assertThat(cuentas.state("Alex")).isEqualTo(AccountState.NEW);
    }

    @Test
    void trasDemasiadosIntentosFallidosSeExpulsa() {
        cuentas.register("Steve", k(1), "s@e.com");
        var flujo = flujo("Steve");
        flujo.hello();
        flujo.onHelloAck(ACK);
        var primero = flujo.onLogin(new LoginPassword(k(2), Optional.empty()));
        assertThat(primero).isNotNull();
        assertThat(primero.kick()).isEmpty();
        assertThat(flujo.onRegister(new Register(k(2), "x@e.com")).kick()).isEmpty();
        var tercero = flujo.onLogin(new LoginPassword(k(2), Optional.empty()));
        assertThat(tercero.kick()).contains(LoginFlow.KICK_TOO_MANY);
        assertThat(tercero.done()).isFalse();
        // Después de la expulsión no se acepta nada más
        fueraDeEstado(() -> flujo.onLogin(new LoginPassword(k(1), Optional.empty())));
    }

    @Test
    void unaVersionMayorDistintaSeExpulsaConSamK002() {
        var flujo = flujo("Steve");
        flujo.hello();
        var respuesta = flujo.onHelloAck(new HelloAck(new ProtocolVersion(2, 0), "9.0", new byte[32]));
        assertThat(respuesta).isEqualTo(new LoginFlow.Reply(Optional.empty(), Optional.of(LoginFlow.KICK_INCOMPATIBLE), false));
        fueraDeEstado(() -> flujo.onRegister(new Register(k(1), "s@e.com")));
        // Una versión menor distinta sí sirve
        var otro = flujo("Alex");
        otro.hello();
        assertThat(otro.onHelloAck(new HelloAck(new ProtocolVersion(1, 7), "1.7", new byte[32]))).isEqualTo(nada());
    }

    @Test
    void losMensajesFueraDeEstadoSonSamP002() {
        var flujo = flujo("Steve");
        fueraDeEstado(() -> flujo.onHelloAck(ACK));
        fueraDeEstado(() -> flujo.onRegister(new Register(k(1), "s@e.com")));
        flujo.hello();
        fueraDeEstado(flujo::hello);
        fueraDeEstado(() -> flujo.onLogin(new LoginPassword(k(1), Optional.empty())));
        flujo.onHelloAck(ACK);
        fueraDeEstado(() -> flujo.onHelloAck(ACK));
        flujo.onRegister(new Register(k(1), "s@e.com"));
        fueraDeEstado(() -> flujo.onLogin(new LoginPassword(k(1), Optional.empty())));
        fueraDeEstado(() -> flujo.onRegister(new Register(k(1), "s@e.com")));
    }
}
