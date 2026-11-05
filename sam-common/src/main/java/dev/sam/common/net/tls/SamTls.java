package dev.sam.common.net.tls;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;

import dev.sam.common.identity.ServerIdentity;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;

/**
 * Perfil TLS de SAM (RS-NET-05, PROTOCOLO.md 3.2): solo TLS 1.3, tres suites AEAD, ALPN
 * {@code sam/1} obligatorio, sin autenticación de cliente y certificado Ed25519 del servidor.
 *
 * <p>Sin reanudación de sesiones (P-09): cada engine de cliente sale de un {@link SSLContext}
 * nuevo, así que nunca ofrece una sesión previa y todo handshake es completo.
 */
public final class SamTls {

    public static final String PROTOCOL = "TLSv1.3";
    public static final String ALPN = "sam/1";
    public static final List<String> CIPHER_SUITES = List.of(
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256");

    private static final char[] NO_PASSWORD = new char[0];

    private SamTls() {
    }

    /**
     * Handlers TLS del servidor, en orden, listos para el pipeline: el {@link SslHandler} y un
     * {@link AlpnGuard}. La JSSE solo rechaza por ALPN si el cliente ofrece la extensión; un cliente
     * TLS cualquiera sin ALPN completaría el handshake, así que el guardia cierra la conexión si al
     * terminar el handshake no se negoció {@code sam/1}, antes de cualquier dato de aplicación.
     */
    public static ChannelHandler[] serverHandlers(ServerIdentity identity) {
        var ssl = new SslHandler(serverEngine(identity));
        return new ChannelHandler[] {ssl, new AlpnGuard(ssl.engine())};
    }

    /** Cierra la conexión si el handshake TLS terminó (bien o mal) sin ALPN {@code sam/1}. */
    static final class AlpnGuard extends ChannelInboundHandlerAdapter {
        private final SSLEngine engine;

        AlpnGuard(SSLEngine engine) {
            this.engine = engine;
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
            // engine.getApplicationProtocol() y no SslHandler.applicationProtocol(): Netty devuelve
            // null en este último cuando el engine es el de la JDK y no uno envuelto por Netty
            if (event instanceof SslHandshakeCompletionEvent && !ALPN.equals(engine.getApplicationProtocol())) {
                ctx.close();
                return;
            }
            ctx.fireUserEventTriggered(event);
        }
    }

    /** Engine de servidor con la identidad (certificado y clave) del servidor. */
    public static SSLEngine serverEngine(ServerIdentity identity) {
        try {
            var keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("sam", identity.privateKey(), NO_PASSWORD, new Certificate[] {identity.certificate()});
            var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, NO_PASSWORD);
            var context = SSLContext.getInstance(PROTOCOL);
            context.init(keyManagers.getKeyManagers(), null, null);
            var engine = context.createSSLEngine();
            engine.setUseClientMode(false);
            // Si el cliente ofrece ALPN sin "sam/1", la JSSE aborta sola (no_application_protocol);
            // si no ofrece ninguno, lo cierra el AlpnGuard
            applyProfile(engine);
            return engine;
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException("No se pudo preparar el TLS del servidor", e);
        }
    }

    /**
     * Engine de cliente: valida el certificado con {@code observer} (pinning, no PKIX) en lugar de
     * autoridades de certificación, y sin verificación de nombre de host.
     */
    public static SSLEngine clientEngine(ServerCertificateObserver observer, String host, int port) {
        try {
            var context = SSLContext.getInstance(PROTOCOL);
            context.init(null, new TrustManager[] {observer}, null);
            var engine = context.createSSLEngine(host, port);
            engine.setUseClientMode(true);
            applyProfile(engine);
            return engine;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo preparar el TLS del cliente", e);
        }
    }

    private static void applyProfile(SSLEngine engine) {
        engine.setEnabledProtocols(new String[] {PROTOCOL});
        engine.setEnabledCipherSuites(CIPHER_SUITES.toArray(String[]::new));
        var parameters = engine.getSSLParameters();
        parameters.setApplicationProtocols(new String[] {ALPN});
        engine.setSSLParameters(parameters);
    }
}
