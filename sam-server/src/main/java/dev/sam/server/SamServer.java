package dev.sam.server;

import java.security.SecureRandom;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.sam.common.auth.Argon2Params;
import dev.sam.common.auth.Argon2id;
import dev.sam.common.identity.ServerFingerprint;
import dev.sam.common.identity.ServerIdentityBootstrap;
import dev.sam.common.identity.ServerIdentityBootstrap.Disabled;
import dev.sam.common.identity.ServerIdentityBootstrap.Ready;
import dev.sam.common.identity.Wordlist;
import dev.sam.common.net.IngressPolicy;
import dev.sam.common.net.IngressPolicy.Transport;
import dev.sam.common.net.gate.IngressGate;
import dev.sam.common.net.gate.IngressRoutes;
import dev.sam.common.net.gate.SamTlsRoutes;
import io.netty.channel.ChannelPipeline;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.loader.api.FabricLoader;

/** Punto de entrada del mod en el servidor dedicado. */
public final class SamServer implements DedicatedServerModInitializer {

    public static final String MOD_ID = "sam-server";
    public static final Logger LOGGER = LoggerFactory.getLogger("SAM");

    // Configuración fija hasta el ciclo de carga del .env (RF-CFG): TCP sí, WebSocket no.
    private static final IngressPolicy INGRESS_POLICY = new IngressPolicy(true, false);
    static final String KICK_MESSAGE = "Este servidor requiere SAM Client para entrar. [SAM-K001]";

    /** Sin identidad cargada, las conexiones SAM se cierran (fallan cerrado, RF-CFG-04). */
    private static volatile IngressRoutes routes = IngressRoutes.closing();

    /** Lo llama el mixin de ServerConnectionListener al armar cada conexión TCP aceptada. */
    public static void installIngressGate(ChannelPipeline pipeline) {
        IngressGate.install(pipeline, INGRESS_POLICY, Transport.DIRECT_TCP, routes, KICK_MESSAGE);
    }

    @Override
    public void onInitializeServer() {
        var version = FabricLoader.getInstance().getModContainer(MOD_ID)
            .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
            .orElse("?");
        LOGGER.info("SAM Server {} cargado. Núcleo: {}", version, coreSmokeCheck());
        loadIdentity();
    }

    private static void loadIdentity() {
        var file = FabricLoader.getInstance().getConfigDir().resolve("sam/keys/identity.p12");
        var outcome = ServerIdentityBootstrap.start(System.getenv(), file, new SecureRandom(), Instant.now());
        if (outcome instanceof Ready ready) {
            var identity = ready.identity();
            routes = new SamTlsRoutes(identity);
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
