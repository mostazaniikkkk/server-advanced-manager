package dev.sam.common.auth;

import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import dev.sam.common.proto.auth.AccountState;
import dev.sam.common.proto.auth.AuthResult;
import dev.sam.common.proto.auth.AuthResult.Status;

/**
 * Registro y login con contraseña (RF-AUTH-01, RS-AUTH-01/05/06, PROTOCOLO.md 5.3 y 6.2). Las
 * respuestas fallidas son genéricas. Cada cambio se entrega a {@code onChange} para persistirlo.
 *
 * <p>Los logins llegan desde varias conexiones a la vez: el estado se sincroniza sobre el servicio.
 * El Argon2 del login corre fuera del candado.
 */
public final class AccountService {

    public static final String LOGIN_FAILED = "Usuario o contraseña incorrectos";
    public static final String REGISTER_FAILED = "No se pudo registrar la cuenta";
    public static final String INVALID_EMAIL = "Correo inválido";
    public static final String INVALID_NICK = "Nombre de usuario no permitido";

    private static final int MAX_EMAIL = 254;
    private static final Pattern EMAIL = Pattern.compile("[^@\\s\\p{Cntrl}]+@[^@\\s\\p{Cntrl}.]+(\\.[^@\\s\\p{Cntrl}.]+)+");

    private final Map<String, Account> accounts = new HashMap<>();
    private final Argon2Params params;
    private final SecureRandom random;
    private final Consumer<List<Account>> onChange;

    public AccountService(Collection<Account> accounts, Argon2Params params, SecureRandom random,
            Consumer<List<Account>> onChange) {
        for (var account : accounts) {
            if (this.accounts.putIfAbsent(account.key(), account) != null) {
                throw new IllegalArgumentException("cuenta repetida: " + account.key());
            }
        }
        this.params = params;
        this.random = random;
        this.onChange = onChange;
    }

    public synchronized AccountState state(String nick) {
        return accounts.containsKey(Nick.normalize(nick)) ? AccountState.REGISTERED : AccountState.NEW;
    }

    public AuthResult register(String nick, byte[] k, String email) {
        if (!Nick.isValid(nick)) {
            return failed(INVALID_NICK);
        }
        if (!isValidEmail(email)) {
            return failed(INVALID_EMAIL);
        }
        var account = new Account(Nick.normalize(nick), nick, PasswordHash.create(k, params, random), email);
        synchronized (this) {
            if (accounts.putIfAbsent(account.key(), account) != null) {
                return failed(REGISTER_FAILED);
            }
            onChange.accept(List.copyOf(accounts.values()));
        }
        return ok();
    }

    public AuthResult login(String nick, byte[] k) {
        Account account;
        synchronized (this) {
            account = accounts.get(Nick.normalize(nick));
        }
        // Sin cuenta, la respuesta es la misma que con la contraseña equivocada (RS-AUTH-05)
        return account != null && PasswordHash.verify(k, account.passwordHash()) ? ok() : failed(LOGIN_FAILED);
    }

    /** Validación básica del correo (RN-36): un {@code @}, sin espacios ni controles, dominio con punto. */
    static boolean isValidEmail(String email) {
        return email.length() <= MAX_EMAIL && EMAIL.matcher(email).matches();
    }

    private static AuthResult ok() {
        return new AuthResult(Status.OK, Optional.empty(), Optional.empty());
    }

    private static AuthResult failed(String detail) {
        return new AuthResult(Status.FAILED, Optional.empty(), Optional.of(detail));
    }
}
