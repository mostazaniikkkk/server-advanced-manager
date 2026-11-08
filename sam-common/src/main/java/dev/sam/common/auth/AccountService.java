package dev.sam.common.auth;

import java.security.SecureRandom;
import java.time.Clock;
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
import dev.sam.common.totp.BackupCodes;
import dev.sam.common.totp.Totp;
import dev.sam.common.totp.TotpState;
import dev.sam.common.totp.TotpVault;

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
    private static final Pattern SIX_DIGITS = Pattern.compile("[0-9]{6}");
    private static final Pattern EMAIL = Pattern.compile("[^@\\s\\p{Cntrl}]+@[^@\\s\\p{Cntrl}.]+(\\.[^@\\s\\p{Cntrl}.]+)+");

    private final Map<String, Account> accounts = new HashMap<>();
    private final Argon2Params params;
    private final SecureRandom random;
    private final Consumer<List<Account>> onChange;
    private final Optional<TotpVault> vault;
    private final Clock clock;
    /** 2FA en activación, hasta que el primer código lo confirme (no se guarda antes). */
    private final Map<String, TotpState> pending = new HashMap<>();

    public AccountService(Collection<Account> accounts, Argon2Params params, SecureRandom random,
            Consumer<List<Account>> onChange) {
        this(accounts, params, random, onChange, Optional.empty(), Clock.systemUTC());
    }

    /** @param vault la bóveda del 2FA; sin ella (no hay SAM_DATA_KEY) el 2FA no se puede activar */
    public AccountService(Collection<Account> accounts, Argon2Params params, SecureRandom random,
            Consumer<List<Account>> onChange, Optional<TotpVault> vault, Clock clock) {
        this.vault = vault;
        this.clock = clock;
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
    public static final String TOTP_UNAVAILABLE = "El 2FA no está disponible en este servidor";
    public static final String TOTP_ALREADY = "El 2FA ya está activo";
    public static final String WRONG_CODE = "Código incorrecto";
    public static final String CODE_REQUIRED = "Falta el código de tu app de 2FA";

    /** Lo que ve el jugador al activar el 2FA: la URI del QR y los códigos de respaldo (una sola vez). */
    public record Enrollment(String uri, List<String> backupCodes) {
    }

    public record TotpBegin(AccountResult result, Optional<Enrollment> enrollment) {
    }

    public synchronized boolean hasTotp(String nick) {
        var account = accounts.get(Nick.normalize(nick));
        return account != null && account.totp().isPresent();
    }

    /**
     * Empieza a activar el 2FA (RF-AUTH-04): con la contraseña, genera el secreto y los códigos de
     * respaldo. No se guarda nada hasta que {@link #confirmTotp} recibe un primer código válido.
     *
     * @param issuer el nombre que verá el jugador en su app
     */
    public TotpBegin beginTotp(String nick, byte[] k, String issuer) {
        if (vault.isEmpty()) {
            return new TotpBegin(accountFailed(TOTP_UNAVAILABLE), Optional.empty());
        }
        if (!verified(nick, k)) {
            return new TotpBegin(accountFailed(WRONG_PASSWORD), Optional.empty());
        }
        synchronized (this) {
            var account = accounts.get(Nick.normalize(nick));
            if (account.totp().isPresent()) {
                return new TotpBegin(accountFailed(TOTP_ALREADY), Optional.empty());
            }
            var secret = Totp.newSecret(random);
            var codes = BackupCodes.generate(random);
            pending.put(account.key(), new TotpState(secret, BackupCodes.hashes(codes), 0));
            return new TotpBegin(accountOk(), Optional.of(new Enrollment(Totp.otpauthUri(issuer, account.nick(), secret), codes)));
        }
    }

    /** El primer código de la app lo activa (prueba que el jugador lo configuró bien). */
    public synchronized AccountResult confirmTotp(String nick, String code) {
        var key = Nick.normalize(nick);
        var state = pending.get(key);
        var checked = state == null || !SIX_DIGITS.matcher(code).matches() ? Optional.<TotpState>empty()
            : Totp.check(state, code, clock.instant());
        if (checked.isEmpty()) {
            return accountFailed(WRONG_CODE);
        }
        pending.remove(key);
        replace(accounts.get(key).withTotp(Optional.of(vault.get().seal(key, checked.get()))));
        return accountOk();
    }

    /**
     * Comprueba un código (o uno de respaldo) y guarda que se usó. Si el 2FA no se puede abrir (falta o
     * cambió la clave de datos), no deja pasar.
     */
    public synchronized AccountResult verifyTotp(String nick, String code) {
        var account = accounts.get(Nick.normalize(nick));
        var state = account == null || vault.isEmpty() ? Optional.<TotpState>empty()
            : account.totp().flatMap(sealed -> vault.get().open(account.key(), sealed));
        var checked = state.flatMap(current -> Totp.check(current, code, clock.instant()));
        if (checked.isEmpty()) {
            return accountFailed(WRONG_CODE);
        }
        replace(account.withTotp(Optional.of(vault.get().seal(account.key(), checked.get()))));
        return accountOk();
    }

    /** Desactivar pide contraseña y código. */
    public AccountResult disableTotp(String nick, byte[] k, String code) {
        if (!verified(nick, k)) {
            return accountFailed(WRONG_PASSWORD);
        }
        synchronized (this) {
            var result = verifyTotp(nick, code);
            if (result.status() != AccountResult.Status.OK) {
                return result;
            }
            replace(accounts.get(Nick.normalize(nick)).withTotp(Optional.empty()));
        }
        return accountOk();
    }

    /** Con 2FA activo, una operación sensible pide el código (5.0); sin 2FA no hace falta. */
    private Optional<AccountResult> secondFactor(String nick, Optional<String> code) {
        if (!hasTotp(nick)) {
            return Optional.empty();
        }
        if (code.isEmpty()) {
            return Optional.of(accountFailed(CODE_REQUIRED));
        }
        var result = verifyTotp(nick, code.get());
        return result.status() == AccountResult.Status.OK ? Optional.empty() : Optional.of(result);
    }

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
        AccountInfo.Totp totp;
        if (account.totp().isPresent()) {
            totp = AccountInfo.Totp.ON;
        } else {
            totp = vault.isPresent() ? AccountInfo.Totp.OFF : AccountInfo.Totp.UNAVAILABLE;
        }
        return new AccountInfo(mask(account.email()), false, google, totp);
    }

    /**
     * Cambio de correo con la contraseña y, con 2FA, el código (RF-AUTH-07b): nunca pide el correo
     * anterior. La contraseña se comprueba antes, así un código no se gasta con la contraseña mala.
     */
    public AccountResult changeEmail(String nick, byte[] k, Optional<String> code, String email) {
        if (!verified(nick, k)) {
            return accountFailed(WRONG_PASSWORD);
        }
        if (!isValidEmail(email)) {
            return accountFailed(INVALID_EMAIL);
        }
        var second = secondFactor(nick, code);
        if (second.isPresent()) {
            return second.get();
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
    public AccountResult unlink(String nick, byte[] k, Optional<String> code, OAuthProvider provider) {
        if (!verified(nick, k)) {
            return accountFailed(WRONG_PASSWORD);
        }
        synchronized (this) {
            var account = accounts.get(Nick.normalize(nick));
            if (provider != OAuthProvider.GOOGLE || account.googleSub().isEmpty()) {
                return accountFailed(NOT_LINKED);
            }
            var second = secondFactor(nick, code);
            if (second.isPresent()) {
                return second.get();
            }
            account = accounts.get(Nick.normalize(nick));
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

    /**
     * {@code sam auth reset} (RF-AUTH-07, RF-ADM-07): borra la cuenta entera; al volver, el jugador la crea de
     * nuevo. Solo lo invoca la consola real.
     *
     * @return si existía
     */
    public synchronized boolean reset(String nick) {
        var key = Nick.normalize(nick);
        pending.remove(key);
        if (accounts.remove(key) == null) {
            return false;
        }
        onChange.accept(List.copyOf(accounts.values()));
        return true;
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
