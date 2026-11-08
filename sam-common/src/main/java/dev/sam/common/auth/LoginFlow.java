package dev.sam.common.auth;

import java.util.List;
import java.util.Optional;

import dev.sam.common.identity.ServerId;
import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.auth.AuthPolicyView;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.AuthResult.Status;
import dev.sam.common.proto.auth.Hello;
import dev.sam.common.proto.auth.HelloAck;
import dev.sam.common.proto.auth.LoginPassword;
import dev.sam.common.proto.auth.LoginTotp;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.auth.ProtocolVersion;
import dev.sam.common.proto.auth.Register;

/**
 * El login de una conexión en la fase de configuration (PROTOCOLO.md 4.4 y 5): HELLO → AUTH → DONE.
 * Un mensaje fuera de estado es SAM-P002. Tras {@code maxAttempts} intentos fallidos, se expulsa
 * con SAM-K004. El dispositivo (5.2) y los scripts (5.5) se agregan en sus ciclos.
 *
 * <p>Los mensajes de una conexión pueden atenderse en otro hilo (Argon2 no corre en el hilo del
 * servidor): el estado se sincroniza sobre el flujo.
 */
public final class LoginFlow {

    public static final String KICK_INCOMPATIBLE = "Tu SAM Client es incompatible con este servidor. [SAM-K002]";
    public static final String KICK_TOO_MANY = "Demasiados intentos fallidos. [SAM-K004]";

    /** El kick de un par o una cuenta bloqueados, con los minutos que faltan (redondeados hacia arriba, mínimo 1). */
    public static String lockedKick(java.time.Duration remaining) {
        var minutes = Math.max(1, (remaining.toSeconds() + 59) / 60);
        return "Demasiados intentos fallidos. Reintenta en " + minutes + " min. [SAM-K004]";
    }

    /**
     * Lo que hay que hacer tras un mensaje del cliente.
     *
     * @param result respuesta para el cliente, si la hay
     * @param kick mensaje de desconexión, si hay que expulsar
     * @param done {@code true} si el login terminó bien: el jugador pasa a jugar
     */
    public record Reply(Optional<AuthResult> result, Optional<String> kick, boolean done) {
    }

    private enum State { NEW, HELLO_SENT, AUTH, TOTP, DONE, CLOSED }

    private final String nick;
    private final ServerId serverId;
    private final String serverName;
    private final AuthPolicyView policy;
    private final AccountService accounts;
    private final int maxAttempts;
    private final LoginThrottle throttle;
    private final String ip;
    private State state = State.NEW;
    private int failures;

    /**
     * @param throttle los intentos entre conexiones (RF-AUTH-06a): un fallo cuenta para el par (cuenta, IP)
     * @param ip la IP del cliente (RS-WS-02), como texto
     */
    public LoginFlow(String nick, ServerId serverId, String serverName, AuthPolicyView policy, AccountService accounts,
            int maxAttempts, LoginThrottle throttle, String ip) {
        this.throttle = throttle;
        this.ip = ip;
        this.nick = nick;
        this.serverId = serverId;
        this.serverName = serverName;
        this.policy = policy;
        this.accounts = accounts;
        this.maxAttempts = maxAttempts;
    }

    public synchronized Hello hello() {
        expect(State.NEW);
        state = State.HELLO_SENT;
        return new Hello(ProtocolVersion.CURRENT, serverId, serverName, List.of(), accounts.state(nick), policy);
    }

    public synchronized Reply onHelloAck(HelloAck ack) {
        expect(State.HELLO_SENT);
        if (ack.protocol().major() != ProtocolVersion.CURRENT.major()) {
            state = State.CLOSED;
            return new Reply(Optional.empty(), Optional.of(KICK_INCOMPATIBLE), false);
        }
        state = State.AUTH;
        return new Reply(Optional.empty(), Optional.empty(), false);
    }

    public synchronized Reply onRegister(Register register) {
        expect(State.AUTH);
        return conclude(accounts.register(nick, register.k(), register.email()));
    }

    public synchronized Reply onLogin(LoginPassword login) {
        expect(State.AUTH);
        return conclude(accounts.login(nick, login.k()));
    }

    public static final String GOOGLE_FAILED = "No se pudo verificar tu cuenta de Google";
    public static final String GOOGLE_NOT_LINKED = "Esa cuenta de Google no está vinculada a este jugador";

    /** Abrir un flujo OAuth solo vale mientras se autentica. */
    public synchronized void startOAuth() {
        expect(State.AUTH);
    }

    /**
     * Entra si ese Google está vinculado a esta misma cuenta (RF-OAUTH-01: no hay registro con Google).
     * Un fallo cuenta para el tope de intentos.
     *
     * @param sub el {@code sub} del ID token ya validado, o vacío si Google no lo confirmó
     */
    public synchronized Reply onGoogle(Optional<String> sub) {
        expect(State.AUTH);
        if (sub.isEmpty()) {
            return conclude(failed(GOOGLE_FAILED));
        }
        var mine = accounts.nickForGoogle(sub.get()).filter(linked -> Nick.normalize(linked).equals(Nick.normalize(nick)));
        return conclude(mine.isPresent() ? new AuthResult(Status.OK, Optional.empty(), Optional.empty()) : failed(GOOGLE_NOT_LINKED));
    }

    private static AuthResult failed(String detail) {
        return new AuthResult(Status.FAILED, Optional.empty(), Optional.of(detail));
    }

    /** El segundo paso (5.0): el código de la app o uno de respaldo. */
    public synchronized Reply onTotp(LoginTotp totp) {
        expect(State.TOTP);
        var checked = accounts.verifyTotp(nick, totp.code());
        if (checked.status() == AccountResult.Status.OK) {
            return done(new AuthResult(Status.OK, Optional.empty(), Optional.empty()));
        }
        return failure(failed(checked.detail().orElse(AccountService.WRONG_CODE)));
    }

    public synchronized boolean done() {
        return state == State.DONE;
    }

    /** Primer paso: si salió bien y la cuenta tiene 2FA, falta el código (5.0). */
    private Reply conclude(AuthResult result) {
        if (result.status() != Status.OK) {
            return failure(result);
        }
        if (accounts.hasTotp(nick)) {
            state = State.TOTP;
            return new Reply(Optional.of(new AuthResult(Status.NEED_TOTP, Optional.empty(), Optional.empty())), Optional.empty(), false);
        }
        return done(result);
    }

    private Reply done(AuthResult result) {
        state = State.DONE;
        throttle.success(nick, ip);
        return new Reply(Optional.of(result), Optional.empty(), true);
    }

    private Reply failure(AuthResult result) {
        var locked = throttle.failure(nick, ip);
        if (locked.isPresent()) {
            state = State.CLOSED;
            return new Reply(Optional.of(result), Optional.of(lockedKick(throttle.remaining(locked.get()))), false);
        }
        if (++failures >= maxAttempts) {
            state = State.CLOSED;
            return new Reply(Optional.of(result), Optional.of(KICK_TOO_MANY), false);
        }
        return new Reply(Optional.of(result), Optional.empty(), false);
    }

    private void expect(State expected) {
        if (state != expected) {
            throw new ProtocolException(ProtocolException.OUT_OF_STATE, "mensaje fuera de estado (" + state + ")");
        }
    }
}
