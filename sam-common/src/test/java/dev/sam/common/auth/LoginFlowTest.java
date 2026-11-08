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
import dev.sam.common.proto.auth.LoginTotp;
import dev.sam.common.proto.auth.ProtocolVersion;
import dev.sam.common.proto.auth.Register;

/** El login de una conexión (PROTOCOLO.md 4.4 y 5): estados, intentos y expulsiones. */
class LoginFlowTest {

    private static final ServerId ID = ServerId.fromHex("45f6c09d17e093f73d707e48bed9de34");
    private static final AuthPolicyView POLITICA = new AuthPolicyView(List.of(AuthMethod.PASSWORD), false, false,
        EmailVerify.LATER, 10);
    private static final HelloAck ACK = new HelloAck(ProtocolVersion.CURRENT, "0.1.0", new byte[32]);

    private final AccountService cuentas = new AccountService(List.of(), new Argon2Params(8, 1, 1), new SecureRandom(), c -> { });

    /** Un tope alto: estos tests prueban el tope por conexión, no el bloqueo (que va aparte). */
    private static final LoginThrottle SIN_BLOQUEO = new LoginThrottle(
        new LoginThrottle.Limits(1000, java.time.Duration.ofMinutes(15), 1000, 1000), java.time.InstantSource.system());

    private LoginFlow flujo(String nick) {
        return new LoginFlow(nick, ID, "Mi Servidor", POLITICA, cuentas, 3, SIN_BLOQUEO, "9.9.9.9", n -> false);
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

    // ===== 2FA como segundo paso (5.0, PROTOCOLO.md 5.3) =====

    /** Una cuenta con el 2FA activo; devuelve el secreto para generar códigos. */
    private byte[] conDosFA(AccountService servicio) {
        servicio.register("Steve", k(1), "s@e.com");
        servicio.linkGoogle("steve", "sub-steve");
        var inicio = servicio.beginTotp("steve", k(1), "S");
        var secreto = AccountTotpTest.secreto(inicio.enrollment().orElseThrow().uri());
        var paso = java.time.Instant.now().getEpochSecond() / dev.sam.common.totp.Totp.PERIOD_SECONDS;
        assertThat(servicio.confirmTotp("steve", dev.sam.common.totp.Totp.code(secreto, paso)).status())
            .isEqualTo(dev.sam.common.proto.account.AccountResult.Status.OK);
        return secreto;
    }

    private static String siguiente(byte[] secreto) {
        // El de la confirmación ya se usó: vale el siguiente paso (ventana de ±1)
        var paso = java.time.Instant.now().getEpochSecond() / dev.sam.common.totp.Totp.PERIOD_SECONDS;
        return dev.sam.common.totp.Totp.code(secreto, paso + 1);
    }

    private AccountService conBoveda() {
        return new AccountService(List.of(), new Argon2Params(8, 1, 1), new SecureRandom(), c -> { },
            Optional.of(new dev.sam.common.totp.TotpVault(dev.sam.common.totp.DataKey.parse(
                dev.sam.common.totp.DataKey.suggest(new SecureRandom())), new SecureRandom())), java.time.Clock.systemUTC());
    }

    private static LoginFlow.Reply necesitaCodigo() {
        return new LoginFlow.Reply(Optional.of(new AuthResult(Status.NEED_TOTP, Optional.empty(), Optional.empty())),
            Optional.empty(), false);
    }

    @Test
    void conDosFALaContrasenaPideElCodigoComoSegundoPaso() {
        var servicio = conBoveda();
        var secreto = conDosFA(servicio);
        var flujo = new LoginFlow("STEVE", ID, "S", POLITICA, servicio, 3, SIN_BLOQUEO, "9.9.9.9", n -> false);
        flujo.hello();
        flujo.onHelloAck(ACK);
        assertThat(flujo.onLogin(new LoginPassword(k(1), Optional.empty()))).isEqualTo(necesitaCodigo());
        assertThat(flujo.done()).isFalse();
        fueraDeEstado(() -> flujo.onLogin(new LoginPassword(k(1), Optional.empty())));
        fueraDeEstado(flujo::startOAuth);
        var malo = flujo.onTotp(new LoginTotp("000000".equals(siguiente(secreto)) ? "111111" : "000000"));
        assertThat(malo.result().get().status()).isEqualTo(Status.FAILED);
        assertThat(malo.result().get().detail()).contains(dev.sam.common.auth.AccountService.WRONG_CODE);
        assertThat(malo.done()).isFalse();
        var bueno = flujo.onTotp(new LoginTotp(siguiente(secreto)));
        assertThat(bueno.result().get().status()).isEqualTo(Status.OK);
        assertThat(bueno.done()).isTrue();
        assertThat(flujo.done()).isTrue();
        fueraDeEstado(() -> flujo.onTotp(new LoginTotp("123456")));
    }

    @Test
    void conDosFAGoogleTambienPideElCodigo() {
        var servicio = conBoveda();
        var secreto = conDosFA(servicio);
        var flujo = new LoginFlow("Steve", ID, "S", POLITICA, servicio, 3, SIN_BLOQUEO, "9.9.9.9", n -> false);
        flujo.hello();
        flujo.onHelloAck(ACK);
        fueraDeEstado(() -> flujo.onTotp(new LoginTotp("123456")));
        assertThat(flujo.onGoogle(Optional.of("sub-steve"))).isEqualTo(necesitaCodigo());
        assertThat(flujo.onTotp(new LoginTotp(siguiente(secreto))).done()).isTrue();
    }

    @Test
    void losCodigosMalosCuentanParaElTopeDeIntentos() {
        var servicio = conBoveda();
        conDosFA(servicio);
        var flujo = new LoginFlow("Steve", ID, "S", POLITICA, servicio, 3, SIN_BLOQUEO, "9.9.9.9", n -> false);
        flujo.hello();
        flujo.onHelloAck(ACK);
        flujo.onLogin(new LoginPassword(k(9), Optional.empty()));
        flujo.onLogin(new LoginPassword(k(1), Optional.empty()));
        assertThat(flujo.onTotp(new LoginTotp("abc")).kick()).as("segundo fallo").isEmpty();
        var tercero = flujo.onTotp(new LoginTotp("abc"));
        assertThat(tercero.kick()).contains(LoginFlow.KICK_TOO_MANY);
    }

    // ===== Bloqueo entre conexiones (RF-AUTH-06a, H-03) =====

    private static final java.time.Instant T0 = java.time.Instant.parse("2026-11-08T12:00:00Z");

    private LoginFlow conectar(String nick, LoginThrottle throttle, String ip) {
        var flujo = new LoginFlow(nick, ID, "S", POLITICA, cuentas, 10, throttle, ip, n -> false);
        flujo.hello();
        flujo.onHelloAck(ACK);
        return flujo;
    }

    @Test
    void reconectarNoReiniciaLosIntentosYElBloqueoDiceCuantoFalta() {
        cuentas.register("Steve", k(1), "s@e.com");
        var throttle = new LoginThrottle(new LoginThrottle.Limits(3, java.time.Duration.ofMinutes(15), 5, 5), () -> T0);
        var primera = conectar("Steve", throttle, "1.1.1.1");
        assertThat(primera.onLogin(new LoginPassword(k(9), Optional.empty())).kick()).isEmpty();
        assertThat(primera.onLogin(new LoginPassword(k(9), Optional.empty())).kick()).isEmpty();
        var segunda = conectar("Steve", throttle, "1.1.1.1");
        var tercero = segunda.onLogin(new LoginPassword(k(9), Optional.empty()));
        assertThat(tercero.result()).hasValueSatisfying(r -> assertThat(r.status()).isEqualTo(Status.FAILED));
        assertThat(tercero.kick()).contains("Demasiados intentos fallidos. Reintenta en 15 min. [SAM-K004]");
        assertThat(segunda.done()).isFalse();
        assertThat(throttle.lockedUntil("steve", "1.1.1.1")).isPresent();
        assertThat(throttle.lockedUntil("steve", "2.2.2.2")).isEmpty();
    }

    @Test
    void unLoginCorrectoLimpiaLosIntentos() {
        cuentas.register("Steve", k(1), "s@e.com");
        var throttle = new LoginThrottle(new LoginThrottle.Limits(3, java.time.Duration.ofMinutes(15), 5, 5), () -> T0);
        var primera = conectar("Steve", throttle, "1.1.1.1");
        primera.onLogin(new LoginPassword(k(9), Optional.empty()));
        primera.onLogin(new LoginPassword(k(9), Optional.empty()));
        assertThat(conectar("Steve", throttle, "1.1.1.1").onLogin(new LoginPassword(k(1), Optional.empty())).done()).isTrue();
        var tercera = conectar("Steve", throttle, "1.1.1.1");
        assertThat(tercera.onLogin(new LoginPassword(k(9), Optional.empty())).kick()).isEmpty();
        assertThat(tercera.onLogin(new LoginPassword(k(9), Optional.empty())).kick()).isEmpty();
    }

    @Test
    void elMensajeDeBloqueoRedondeaLosMinutosHaciaArriba() {
        assertThat(LoginFlow.lockedKick(java.time.Duration.ofSeconds(61))).isEqualTo("Demasiados intentos fallidos. Reintenta en 2 min. [SAM-K004]");
        assertThat(LoginFlow.lockedKick(java.time.Duration.ofSeconds(60))).contains("en 1 min.");
        assertThat(LoginFlow.lockedKick(java.time.Duration.ofSeconds(1))).contains("en 1 min.");
        assertThat(LoginFlow.lockedKick(java.time.Duration.ZERO)).contains("en 1 min.");
        assertThat(LoginFlow.lockedKick(java.time.Duration.ofHours(24))).contains("en 1440 min.");
    }

    // ===== Admin sin 2FA: enrolamiento obligatorio (RF-ADM-03a, H-02) =====

    private LoginFlow admin(AccountService servicio, String nick) {
        var flujo = new LoginFlow(nick, ID, "Mi Servidor", POLITICA, servicio, 3, SIN_BLOQUEO, "9.9.9.9",
            n -> n.equalsIgnoreCase("steve"));
        flujo.hello();
        flujo.onHelloAck(ACK);
        return flujo;
    }

    private static String ahora(byte[] secreto) {
        var paso = java.time.Instant.now().getEpochSecond() / dev.sam.common.totp.Totp.PERIOD_SECONDS;
        return dev.sam.common.totp.Totp.code(secreto, paso);
    }

    @Test
    void unAdminSinDosFADebeEnrolarseAntesDeEntrar() {
        var servicio = conBoveda();
        servicio.register("Steve", k(1), "s@e.com");
        var flujo = admin(servicio, "Steve");
        var respuesta = flujo.onLogin(new LoginPassword(k(1), Optional.empty()));
        assertThat(respuesta.result()).contains(new AuthResult(Status.NEED_ENROLL, Optional.empty(),
            Optional.of(LoginFlow.ENROLL_REQUIRED)));
        assertThat(respuesta.done()).isFalse();
        assertThat(respuesta.kick()).isEmpty();
        var inscripcion = respuesta.enroll().orElseThrow();
        assertThat(inscripcion.uri()).startsWith("otpauth://totp/").contains("Mi%20Servidor");
        assertThat(inscripcion.backupCodes()).hasSize(10);
        assertThat(flujo.done()).isFalse();
        // Mientras no confirma, no puede volver a intentar la contraseña
        fueraDeEstado(() -> flujo.onLogin(new LoginPassword(k(1), Optional.empty())));
        var secreto = AccountTotpTest.secreto(inscripcion.uri());
        var malo = flujo.onEnrollConfirm(new dev.sam.common.proto.account.TotpConfirm("000000".equals(ahora(secreto)) ? "111111" : "000000"));
        assertThat(malo.result().orElseThrow().status()).isEqualTo(Status.FAILED);
        assertThat(malo.done()).isFalse();
        var bueno = flujo.onEnrollConfirm(new dev.sam.common.proto.account.TotpConfirm(ahora(secreto)));
        assertThat(bueno.done()).isTrue();
        assertThat(bueno.result().orElseThrow().status()).isEqualTo(Status.OK);
        assertThat(servicio.hasTotp("steve")).isTrue();
        assertThat(flujo.done()).isTrue();
    }

    @Test
    void losCodigosMalosDelEnrolamientoCuentanParaElTope() {
        var servicio = conBoveda();
        servicio.register("Steve", k(1), "s@e.com");
        var flujo = admin(servicio, "Steve");
        flujo.onLogin(new LoginPassword(k(9), Optional.empty()));
        flujo.onLogin(new LoginPassword(k(1), Optional.empty()));
        assertThat(flujo.onEnrollConfirm(new dev.sam.common.proto.account.TotpConfirm("abc")).kick()).as("segundo fallo").isEmpty();
        var tercero = flujo.onEnrollConfirm(new dev.sam.common.proto.account.TotpConfirm("abc"));
        assertThat(tercero.kick()).contains(LoginFlow.KICK_TOO_MANY);
    }

    @Test
    void unJugadorNormalOUnAdminConDosFANoSeEnrolan() {
        var servicio = conBoveda();
        servicio.register("Alex", k(2), "a@e.com");
        var normal = admin(servicio, "Alex");
        var respuesta = normal.onLogin(new LoginPassword(k(2), Optional.empty()));
        assertThat(respuesta.done()).isTrue();
        assertThat(respuesta.enroll()).isEmpty();
        conDosFA(servicio);
        assertThat(admin(servicio, "Steve").onLogin(new LoginPassword(k(1), Optional.empty()))).isEqualTo(necesitaCodigo());
        fueraDeEstado(() -> admin(servicio, "Alex").onEnrollConfirm(new dev.sam.common.proto.account.TotpConfirm("123456")));
    }

    @Test
    void sinBovedaElAdminEntraIgualSinEnrolarse() {
        cuentas.register("Steve", k(1), "s@e.com");
        var flujo = admin(cuentas, "Steve");
        var respuesta = flujo.onLogin(new LoginPassword(k(1), Optional.empty()));
        assertThat(respuesta.done()).isTrue();
        assertThat(respuesta.enroll()).isEmpty();
    }

    @Test
    void conGoogleTambienSeEnrola() {
        var servicio = conBoveda();
        servicio.register("Steve", k(1), "s@e.com");
        servicio.linkGoogle("steve", "sub-steve");
        var flujo = admin(servicio, "Steve");
        var respuesta = flujo.onGoogle(Optional.of("sub-steve"));
        assertThat(respuesta.result().orElseThrow().status()).isEqualTo(Status.NEED_ENROLL);
        assertThat(respuesta.enroll()).isPresent();
    }

    // ===== Entrar con Google (REQUERIMIENTOS 5.5) =====

    private LoginFlow enAuth(String nick) {
        var flujo = flujo(nick);
        flujo.hello();
        flujo.onHelloAck(ACK);
        return flujo;
    }

    @Test
    void conSuGoogleVinculadoEntra() {
        cuentas.register("Steve", k(1), "s@e.com");
        cuentas.linkGoogle("steve", "sub-steve");
        var flujo = enAuth("STEVE");
        flujo.startOAuth();
        var respuesta = flujo.onGoogle(Optional.of("sub-steve"));
        assertThat(respuesta.result()).hasValueSatisfying(r -> assertThat(r.status()).isEqualTo(Status.OK));
        assertThat(respuesta.done()).isTrue();
        assertThat(flujo.done()).isTrue();
    }

    @Test
    void unGoogleAjenoOSinVerificarFallaYCuentaComoIntento() {
        cuentas.register("Steve", k(1), "s@e.com");
        cuentas.register("Alex", k(2), "a@e.com");
        cuentas.linkGoogle("alex", "sub-alex");
        var flujo = enAuth("Steve");
        var ajeno = flujo.onGoogle(Optional.of("sub-alex"));
        assertThat(ajeno).isEqualTo(new LoginFlow.Reply(Optional.of(new AuthResult(Status.FAILED, Optional.empty(),
            Optional.of(LoginFlow.GOOGLE_NOT_LINKED))), Optional.empty(), false));
        assertThat(flujo.onGoogle(Optional.of("sub-nadie")).result().get().detail()).contains(LoginFlow.GOOGLE_NOT_LINKED);
        var tercero = flujo.onGoogle(Optional.empty());
        assertThat(tercero.result().get().detail()).contains(LoginFlow.GOOGLE_FAILED);
        assertThat(tercero.kick()).contains(LoginFlow.KICK_TOO_MANY);
        assertThat(flujo.done()).isFalse();
    }

    @Test
    void oauthSoloEnLaAutenticacion() {
        var flujo = flujo("Steve");
        fueraDeEstado(flujo::startOAuth);
        flujo.hello();
        fueraDeEstado(() -> flujo.onGoogle(Optional.of("x")));
        flujo.onHelloAck(ACK);
        flujo.startOAuth();
        flujo.startOAuth();
        cuentas.register("Steve", k(1), "s@e.com");
        flujo.onLogin(new LoginPassword(k(1), Optional.empty()));
        fueraDeEstado(flujo::startOAuth);
        fueraDeEstado(() -> flujo.onGoogle(Optional.of("x")));
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
