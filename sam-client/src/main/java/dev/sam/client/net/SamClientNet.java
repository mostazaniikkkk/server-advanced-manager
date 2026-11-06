package dev.sam.client.net;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Optional;

import org.slf4j.Logger;

import dev.sam.common.identity.PinStore;
import dev.sam.common.identity.PinStore.Verdict;
import dev.sam.common.identity.PinStoreJson;
import dev.sam.common.identity.ServerFingerprint;
import dev.sam.common.identity.ServerId;
import dev.sam.common.net.ServerAddress;
import dev.sam.common.net.StatusProbe;
import dev.sam.common.net.tls.SamTls;
import dev.sam.common.net.tls.ServerCertificateObserver;
import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;

/**
 * El TLS de SAM en el cliente (PROTOCOLO.md 2.4 y 3): antes de conectar, una dirección fijada va
 * siempre por TLS y una no fijada se sondea; si anuncia SAM, va por TLS. Tras el handshake se
 * verifica el pin: la primera vez se fija (TOFU), un cambio de identidad o de clave corta la conexión
 * (SAM-C001/C002).
 *
 * <p>MVP: la primera conexión se acepta sin la pantalla de confirmación (RS-NET-09); la huella queda
 * en el log. La pantalla llega en su ciclo.
 */
public final class SamClientNet {

    public static final String TLS_NAME = "sam_tls";
    private static final int PROBE_TIMEOUT_MILLIS = 3000;

    /** A dónde va una conexión por TLS. */
    public record Plan(ServerAddress address, String host, int port) {
    }

    private static Logger log;
    private static Path pinsFile;
    private static volatile PinStore pins = PinStore.empty();
    /** El server_id verificado de la última conexión TLS: el hello del servidor debe coincidir. */
    private static volatile ServerId lastVerified;
    private static volatile String lastFingerprint;

    private SamClientNet() {
    }

    public static synchronized void init(Path file, Logger logger) {
        log = logger;
        pinsFile = file;
        if (Files.exists(file)) {
            try {
                var loaded = PinStoreJson.decode(Files.readString(file));
                pins = loaded.store();
                loaded.problems().forEach(problem -> log.warn("pins.json: {}", problem));
            } catch (IOException e) {
                log.error("No se pudo leer {}: {}", file, e.getMessage());
            }
        }
    }

    /** La dirección que escribió el jugador (ConnectScreen), para fijar el pin con ese nombre. */
    private static volatile String typedHost;
    private static volatile int typedPort;

    public static void typed(String host, int port) {
        typedHost = host;
        typedPort = port;
    }

    /** En el hilo del conector, antes de abrir el socket: decide si la conexión va por TLS. */
    public static void prepare(InetSocketAddress target, Object connection) {
        // getHostString puede traer un nombre inverso (p. ej. de hosts): vale lo que escribió el jugador
        var host = typedHost != null && typedPort == target.getPort() ? typedHost : target.getAddress().getHostAddress();
        ServerAddress address;
        try {
            address = ServerAddress.parse(host + ":" + target.getPort());
        } catch (IllegalArgumentException e) {
            return;
        }
        var sam = pins.isPinned(address) || StatusProbe.probe(host, target, PROBE_TIMEOUT_MILLIS).isPresent();
        if (sam) {
            ((SamTlsConnection) connection).sam$setPlan(new Plan(address, host, target.getPort()));
        }
    }

    /** Al activarse el canal: el TLS va primero, pegado al socket. */
    public static void install(Channel channel, Plan plan) {
        if (plan == null || channel.pipeline().get(TLS_NAME) != null) {
            return;
        }
        var observer = new ServerCertificateObserver();
        var tls = new SslHandler(SamTls.clientEngine(observer, plan.host(), plan.port()));
        channel.pipeline().addFirst(TLS_NAME, tls);
        tls.handshakeFuture().addListener(done -> {
            if (!done.isSuccess()) {
                log.warn("TLS de SAM con {} falló: {}", plan.address(), done.cause().toString());
                return;
            }
            var observed = observer.observed();
            if (observed.isEmpty() || !accept(plan, observed.get())) {
                channel.close();
            }
        });
    }

    public static Optional<ServerId> lastVerified() {
        return Optional.ofNullable(lastVerified);
    }

    /** La huella en palabras del último servidor verificado (PROTOCOLO.md 3.5). */
    public static Optional<String> lastFingerprint() {
        return Optional.ofNullable(lastFingerprint);
    }

    private static synchronized boolean accept(Plan plan, ServerCertificateObserver.ObservedServer server) {
        var verdict = pins.verify(plan.address(), server.serverId(), server.publicKey());
        var fingerprint = ServerFingerprint.of(server.publicKey().pin().toBytes()).phrase();
        switch (verdict) {
            case Verdict.Trusted trusted -> {
                if (trusted.newAddress()) {
                    save(pins.addAddress(plan.address(), server.serverId()));
                }
            }
            case Verdict.FirstContact first -> {
                log.info("Primera conexión con {}: server_id {}, huella «{}». Se fija (TOFU).", plan.address(),
                    server.serverId().hex(), fingerprint);
                save(pins.trust(plan.address(), server.serverId(), server.publicKey(), plan.host(), Instant.now()));
            }
            case Verdict.Rotated rotated -> save(pins.replaceKey(server.serverId(), rotated.newKey()));
            case Verdict.IdentityMismatch mismatch -> {
                log.error("[{}] {} presenta otro servidor (server_id {}, se esperaba {}). Conexión cortada.", mismatch.code(),
                    plan.address(), mismatch.presented().hex(), mismatch.expected().hex());
                return false;
            }
            case Verdict.KeyChanged changed -> {
                log.error("[{}] {} cambió de clave sin rotación válida (huella «{}»). Conexión cortada.", changed.code(),
                    plan.address(), fingerprint);
                return false;
            }
        }
        lastVerified = server.serverId();
        lastFingerprint = fingerprint;
        return true;
    }

    private static void save(PinStore updated) {
        pins = updated;
        try {
            Files.createDirectories(pinsFile.getParent());
            var temp = Files.createTempFile(pinsFile.getParent(), ".pins", ".tmp");
            Files.writeString(temp, PinStoreJson.encode(updated));
            Files.move(temp, pinsFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            log.error("No se pudo guardar {}: {}", pinsFile, e.getMessage());
        }
    }
}
