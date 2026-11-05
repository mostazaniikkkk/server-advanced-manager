package dev.sam.server;

import java.security.SecureRandom;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.sam.common.auth.Argon2Params;
import dev.sam.common.auth.Argon2id;
import dev.sam.common.config.TransportConfig;
import dev.sam.common.identity.ServerFingerprint;
import dev.sam.common.identity.ServerIdentityBootstrap;
import dev.sam.common.identity.ServerIdentityBootstrap.Disabled;
import dev.sam.common.identity.ServerIdentityBootstrap.Ready;
import dev.sam.common.identity.Wordlist;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Action;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.ProtocolDetector.Classification;
import dev.sam.common.net.gate.IngressGate;
import dev.sam.common.net.gate.IngressRoutes;
import dev.sam.common.net.gate.SamRoutes;
import io.netty.channel.ChannelPipeline;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.loader.api.FabricLoader;

/** Punto de entrada del mod en el servidor dedicado. */
public final class SamServer implements DedicatedServerModInitializer {

    public static final String MOD_ID = "sam-server";
    public static final Logger LOGGER = LoggerFactory.getLogger("SAM");

    static final String KICK_MESSAGE = "Este servidor requiere SAM Client para entrar. [SAM-K001]";

    private record Ingress(IngressPolicy policy, IngressRoutes routes) {
    }

    /**
     * Hasta cargar configuración e identidad: solo TCP y las conexiones SAM se cierran (fallan
     * cerrado, RF-CFG-04). Política y rutas cambian juntas.
     */
    private static volatile Ingress ingress = new Ingress(new IngressPolicy(true, false), IngressRoutes.closing());

    /** Lo llama el mixin de ServerConnectionListener al armar cada conexión TCP aceptada. */
    public static void installIngressGate(ChannelPipeline pipeline) {
        var current = ingress;
        IngressGate.install(pipeline, current.policy(), Transport.DIRECT_TCP, current.routes(), KICK_MESSAGE);
    }

    @Override
    public void onInitializeServer() {
        var version = FabricLoader.getInstance().getModContainer(MOD_ID)
            .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
            .orElse("?");
        LOGGER.info("SAM Server {} cargado. Núcleo: {}", version, coreSmokeCheck());
        // Hasta el ciclo del .env, el transporte sale de las variables de entorno (RF-CFG-02: tienen prioridad)
        TransportConfig transport;
        try {
            transport = TransportConfig.from(System.getenv());
        } catch (IllegalArgumentException e) {
            LOGGER.error("Configuración de transporte inválida: {}. El login de SAM queda cerrado.", e.getMessage());
            return;
        }
        loadIdentity(transport);
    }

    private static void loadIdentity(TransportConfig transport) {
        var file = FabricLoader.getInstance().getConfigDir().resolve("sam/keys/identity.p12");
        var outcome = ServerIdentityBootstrap.start(System.getenv(), file, new SecureRandom(), Instant.now());
        if (outcome instanceof Ready ready) {
            var identity = ready.identity();
            // Hasta que exista la auditoría encadenada, los eventos de la entrada van al log
            var realIp = transport.realIp(message -> LOGGER.warn("[auditoría] {}", message));
            ingress = new Ingress(transport.policy(), new SamRoutes(identity, transport.webSocketPath(), realIp));
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
     * Comprueba que el núcleo embebido (sam-common y BouncyCastle, jar-in-jar) carga: lee un
     * recurso del jar anidado y ejecuta un Argon2 mínimo.
     */
    static String coreSmokeCheck() {
        var words = Wordlist.spanish().size();
        var argon2 = Argon2id.hash(new byte[] {1}, new byte[8], new Argon2Params(8, 1, 1), 16).length;
        return words + " palabras de huella, Argon2 " + (argon2 == 16 ? "OK" : "FALLA");
    }
}
