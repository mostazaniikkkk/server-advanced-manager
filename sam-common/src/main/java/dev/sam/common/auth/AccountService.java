package dev.sam.common.auth;

import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import dev.sam.common.proto.account.AccountInfo;
import dev.sam.common.proto.account.AccountResult;
import dev.sam.common.proto.account.OAuthProvider;
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

    public static final String WRONG_PASSWORD = "Contraseña incorrecta";
    public static final String GOOGLE_TAKEN = "Esa cuenta de Google ya está vinculada a otro jugador";
    public static final String GOOGLE_ALREADY = "Tu cuenta ya tiene Google vinculado";
    public static final String NOT_LINKED = "No hay una cuenta vinculada de ese proveedor";

    /**
     * Lo que muestra "Opciones de cuenta" (RF-AUTH-07d). El correo va enmascarado; hasta que exista el
     * envío de correos ninguno está verificado.
     *
     * @param googleAvailable el servidor tiene Google configurado
     */
    public synchronized AccountInfo info(String nick, boolean googleAvailable) {
        var account = accounts.get(Nick.normalize(nick));
        AccountInfo.Google google;
        if (!googleAvailable) {
            google = AccountInfo.Google.UNAVAILABLE;
        } else {
            google = account.googleSub().isPresent() ? AccountInfo.Google.LINKED : AccountInfo.Google.AVAILABLE;
        }
        return new AccountInfo(mask(account.email()), false, google);
    }

    /** Cambio de correo con la contraseña (RF-AUTH-07b): nunca pide el correo anterior. */
    public AccountResult changeEmail(String nick, byte[] k, String email) {
        if (!verified(nick, k)) {
            return accountFailed(WRONG_PASSWORD);
        }
        if (!isValidEmail(email)) {
            return accountFailed(INVALID_EMAIL);
        }
        synchronized (this) {
            var account = accounts.get(Nick.normalize(nick));
            replace(account.withEmail(email));
        }
        return accountOk();
    }

    /**
     * Vincula Google por su {@code sub} (RF-OAUTH-02/03): una cuenta de Google va a una sola cuenta del
     * servidor y cada cuenta tiene como mucho una. Quien llama ya validó el ID token.
     */
    public synchronized AccountResult linkGoogle(String nick, String sub) {
        var account = accounts.get(Nick.normalize(nick));
        if (account == null || account.googleSub().isPresent()) {
            return accountFailed(GOOGLE_ALREADY);
        }
        if (nickForGoogle(sub).isPresent()) {
            return accountFailed(GOOGLE_TAKEN);
        }
        replace(account.withGoogleSub(Optional.of(sub)));
        return accountOk();
    }

    /** Desvincula con la contraseña (RF-OAUTH-02): la contraseña siempre existe, así que nunca deja la cuenta sin acceso. */
    public AccountResult unlink(String nick, byte[] k, OAuthProvider provider) {
        if (!verified(nick, k)) {
            return accountFailed(WRONG_PASSWORD);
        }
        synchronized (this) {
            var account = accounts.get(Nick.normalize(nick));
            if (provider != OAuthProvider.GOOGLE || account.googleSub().isEmpty()) {
                return accountFailed(NOT_LINKED);
            }
            replace(account.withGoogleSub(Optional.empty()));
        }
        return accountOk();
    }

    /** La cuenta vinculada a ese {@code sub} de Google, por su nick. */
    public synchronized Optional<String> nickForGoogle(String sub) {
        return accounts.values().stream().filter(a -> a.googleSub().filter(sub::equals).isPresent()).map(Account::nick).findFirst();
    }

    /** {@code steve@example.com} → {@code s***@e***.com} (RS-AUTH-07). */
    static String mask(String email) {
        var at = email.indexOf('@');
        var domain = email.substring(at + 1);
        return email.charAt(0) + "***@" + domain.charAt(0) + "***" + domain.substring(domain.lastIndexOf('.'));
    }

    /** Argon2 fuera del candado, como el login. */
    private boolean verified(String nick, byte[] k) {
        Account account;
        synchronized (this) {
            account = accounts.get(Nick.normalize(nick));
        }
        return account != null && PasswordHash.verify(k, account.passwordHash());
    }

    private void replace(Account account) {
        accounts.put(account.key(), account);
        onChange.accept(List.copyOf(accounts.values()));
    }

    private static AccountResult accountOk() {
        return new AccountResult(AccountResult.Status.OK, Optional.empty());
    }

    private static AccountResult accountFailed(String detail) {
        return new AccountResult(AccountResult.Status.FAILED, Optional.of(detail));
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
