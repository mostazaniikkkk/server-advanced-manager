package dev.sam.server;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.sam.common.auth.AccountService;
import dev.sam.common.auth.AccountsFile;
import dev.sam.common.auth.Argon2Params;
import dev.sam.common.auth.Argon2id;
import dev.sam.common.config.EnvFile;
import dev.sam.common.config.ServerEnv;
import dev.sam.common.config.TransportConfig;
import dev.sam.common.identity.ServerFingerprint;
import dev.sam.common.identity.ServerId;
import dev.sam.common.identity.ServerIdentityBootstrap;
import dev.sam.common.identity.ServerIdentityBootstrap.Disabled;
import dev.sam.common.identity.ServerIdentityBootstrap.Ready;
import dev.sam.common.identity.Wordlist;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.StatusAdvert;
import dev.sam.common.net.IngressPolicy.Action;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ProtocolDetector.Classification;
import dev.sam.common.net.gate.ConnectionGuard;
import dev.sam.common.net.gate.IngressGate;
import dev.sam.common.net.gate.IngressRoutes;
import dev.sam.common.net.gate.SamRoutes;
import dev.sam.common.proto.auth.AuthMethod;
import dev.sam.common.proto.auth.AuthPolicyView;
import dev.sam.common.proto.auth.EmailVerify;
import dev.sam.server.auth.GoogleSignIn;
import dev.sam.server.auth.SamAccount;
import dev.sam.server.auth.SamAuth;
import io.netty.channel.ChannelPipeline;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.loader.api.FabricLoader;

/** Punto de entrada del mod en el servidor dedicado. */
public final class SamServer implements DedicatedServerModInitializer {

    public static final String MOD_ID = "sam-server";
    public static final Logger LOGGER = LoggerFactory.getLogger("SAM");

    static final String PASSWORD_MIN_LENGTH = "SAM_PASSWORD_MIN_LENGTH";
    private static final SamAuth AUTH = new SamAuth(LOGGER);
    private static final SamAccount ACCOUNT = new SamAccount(LOGGER);

    static final String KICK_MESSAGE = "Este servidor requiere SAM Client para entrar. [SAM-K001]";

    private record Ingress(IngressPolicy policy, IngressRoutes routes, ConnectionGuard guard) {
    }

    /**
     * Hasta cargar configuración e identidad: solo TCP y las conexiones SAM se cierran (fallan
     * cerrado, RF-CFG-04). Política y rutas cambian juntas.
     */
    private static volatile Ingress ingress = new Ingress(new IngressPolicy(true, false), IngressRoutes.closing(),
        new ConnectionGuard(ConnectionGuard.DEFAULT_PER_IP, ConnectionGuard.DEFAULT_GLOBAL, address -> false));

    /** Solo con la identidad cargada: anunciar SAM sin poder atender TLS dejaría al cliente sin entrar. */
    private static volatile Optional<StatusAdvert> statusAdvert = Optional.empty();

    /** El campo sam de la respuesta de estado (PROTOCOLO.md 2.4); lo usa el mixin del estado. */
    public static Optional<StatusAdvert> statusAdvert() {
        return statusAdvert;
    }

    /** Lo llama el mixin de ServerConnectionListener al armar cada conexión TCP aceptada. */
    public static void installIngressGate(ChannelPipeline pipeline) {
        var current = ingress;
        IngressGate.install(pipeline, current.policy(), Transport.DIRECT_TCP, current.routes(), KICK_MESSAGE, current.guard());
    }

    @Override
    public void onInitializeServer() {
        var version = FabricLoader.getInstance().getModContainer(MOD_ID)
            .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
            .orElse("?");
        LOGGER.info("SAM Server {} cargado. Núcleo: {}", version, coreSmokeCheck());
        AUTH.install();
        ACCOUNT.install();
        TransportConfig transport;
        Map<String, String> config;
        try {
            config = loadConfig();
            transport = TransportConfig.from(config);
        } catch (IllegalArgumentException | IOException e) {
            LOGGER.error("Configuración inválida: {}. El login de SAM queda cerrado.", e.getMessage());
            return;
        }
        // Scripts Lua (RF-LUA-01..03): independientes del login; sin firma de confianza no corre nada
        dev.sam.server.scripts.SamScripts.install(LOGGER, FabricLoader.getInstance().getConfigDir().resolve("sam/keys"), config);
        // Los límites aplican aunque el login de SAM quede cerrado: el vanilla también pasa por la compuerta
        ingress = new Ingress(ingress.policy(), ingress.routes(), transport.guard());
        loadIdentity(transport, config);
    }

    /**
     * El .env (lo genera si falta) más el entorno real del proceso, que gana (RF-CFG-01/02/03). El .env
     * no puede estar dentro del mundo (RF-CFG-09).
     */
    private static Map<String, String> loadConfig() throws IOException {
        var gameDir = FabricLoader.getInstance().getGameDir();
        var file = EnvFile.locate(gameDir, System.getenv());
        var loaded = EnvFile.load(file, List.of(gameDir.resolve(levelName(gameDir))), new SecureRandom());
        if (loaded.created()) {
            LOGGER.info("Configuración: se generó {} con valores por defecto (documentado en {})", file, EnvFile.EXAMPLE_NAME);
        } else {
            LOGGER.info("Configuración: {} ({} claves)", file, loaded.values().size());
        }
        loaded.warnings().forEach(LOGGER::warn);
        return ServerEnv.merge(loaded.values(), System.getenv());
    }

    /** La carpeta del mundo según server.properties (por defecto, world). */
    private static String levelName(Path gameDir) throws IOException {
        var properties = new Properties();
        var file = gameDir.resolve("server.properties");
        if (Files.exists(file)) {
            try (var in = Files.newInputStream(file)) {
                properties.load(in);
            }
        }
        return properties.getProperty("level-name", "world");
    }

    private static void loadIdentity(TransportConfig transport, Map<String, String> config) {
        var file = FabricLoader.getInstance().getConfigDir().resolve("sam/keys/identity.p12");
        var outcome = ServerIdentityBootstrap.start(System.getenv(), file, new SecureRandom(), Instant.now());
        if (outcome instanceof Ready ready) {
            var identity = ready.identity();
            // Hasta que exista la auditoría encadenada, los eventos de la entrada van al log
            var realIp = transport.realIp(message -> LOGGER.warn("[auditoría] {}", message));
            var loginOpen = startAuth(identity.serverId(), config);
            ingress = new Ingress(transport.policy(), new SamRoutes(identity, transport.webSocketPath(), realIp, loginOpen),
                ingress.guard());
            statusAdvert = Optional.of(new StatusAdvert(identity.serverId()));
            LOGGER.info("Transporte: TCP directo {}, WebSocket {}",
                transport.policy().decide(Transport.DIRECT_TCP, Classification.TLS) == Action.SAM_TLS ? "sí" : "no",
                transport.webSocketPath().isPresent()
                    ? "sí (ruta configurada, IP real por " + transport.realIpHeader().headerName() + ")"
                    : "no");
            var fingerprint = ServerFingerprint.of(identity.publicKey().pin().toBytes());
            LOGGER.info("Identidad del servidor {}: server_id {}, huella «{}»",
                ready.created() ? "generada" : "cargada", identity.serverId().hex(), fingerprint.phrase());
        } else if (outcome instanceof Disabled disabled) {
            LOGGER.error(disabled.reason());
            // RF-CFG-08: el valor sugerido se muestra una sola vez y no se guarda
            disabled.suggestedPassphrase().ifPresent(value -> LOGGER.warn(
                "Valor sugerido para {} (defínelo como variable de entorno del proceso, nunca en el .env): {}",
                ServerIdentityBootstrap.PASSPHRASE_ENV, value));
        }
    }

    /**
     * Cuentas y política de login (MVP: solo contraseña). Si las cuentas no se pueden leer, el login
     * queda cerrado: arrancar sin ellas dejaría registrar de nuevo el nick de otro (RF-CFG-04).
     */
    private static boolean startAuth(ServerId serverId, Map<String, String> config) {
        var file = FabricLoader.getInstance().getConfigDir().resolve("sam/accounts.json");
        try {
            var minPassword = Integer.parseInt(config.getOrDefault(PASSWORD_MIN_LENGTH, "6").strip());
            // "Entrar con Google" solo con credenciales del operador (REQUERIMIENTOS 5.5); el secreto no se muestra
            var google = GoogleSignIn.fromConfig(config);
            var methods = google.isPresent() ? List.of(AuthMethod.PASSWORD, AuthMethod.GOOGLE) : List.of(AuthMethod.PASSWORD);
            var policy = new AuthPolicyView(methods, false, false, EmailVerify.LATER, minPassword);
            var accounts = new AccountService(AccountsFile.load(file), Argon2Params.SERVER_DEFAULT, new SecureRandom(),
                all -> {
                    try {
                        AccountsFile.save(file, all);
                    } catch (IOException e) {
                        throw new UncheckedIOException("No se pudieron guardar las cuentas en " + file, e);
                    }
                }, dataVault(config), java.time.Clock.systemUTC());
            AUTH.activate(new SamAuth.Setup(accounts, serverId, policy, google));
            ACCOUNT.activate(new SamAccount.Setup(accounts, google));
            LOGGER.info("Login de SAM abierto: contraseña{}; {} cuentas en {}",
                google.map(g -> " y Google (client_id " + g.clientId() + ")").orElse(""), AccountsFile.load(file).size(), file);
            return true;
        } catch (IOException | IllegalArgumentException e) {
            LOGGER.error("Cuentas o política de login inválidas: {}. El login de SAM queda cerrado.", e.getMessage());
            return false;
        }
    }

    /**
     * La bóveda del 2FA (RS-AUTH-03) con {@code SAM_DATA_KEY}, que solo puede venir del entorno del proceso
     * (el .env la rechaza, RF-CFG-08). Sin ella el 2FA no se puede activar; el login sigue.
     */
    private static java.util.Optional<dev.sam.common.totp.TotpVault> dataVault(Map<String, String> config) {
        var value = config.get(dev.sam.common.totp.DataKey.ENV);
        if (value == null || value.isBlank()) {
            LOGGER.warn("2FA no disponible: falta {} en el entorno del proceso. Valor sugerido (defínelo como variable de "
                + "entorno, nunca en el .env; guárdalo: sin él no se pueden verificar los 2FA activos): {}",
                dev.sam.common.totp.DataKey.ENV, dev.sam.common.totp.DataKey.suggest(new SecureRandom()));
            return java.util.Optional.empty();
        }
        try {
            var key = dev.sam.common.totp.DataKey.parse(value);
            LOGGER.info("2FA disponible (clave de datos cargada)");
            return java.util.Optional.of(new dev.sam.common.totp.TotpVault(key, new SecureRandom()));
        } catch (IllegalArgumentException e) {
            LOGGER.error("2FA no disponible: {}", e.getMessage());
            return java.util.Optional.empty();
        }
    }

    /**
     * Comprueba que el núcleo embebido (sam-common y BouncyCastle, jar-in-jar) carga: lee un
     * recurso del jar anidado y ejecuta un Argon2 mínimo.
     */
    static String coreSmokeCheck() {
        var words = Wordlist.spanish().size();
        var argon2 = Argon2id.hash(new byte[] {1}, new byte[8], new Argon2Params(8, 1, 1), 16).length;
        return words + " palabras de huella, Argon2 " + (argon2 == 16 ? "OK" : "FALLA");
    }
}
