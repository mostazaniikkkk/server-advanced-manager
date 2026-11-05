package dev.sam.common.net.tls;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

import dev.sam.common.identity.ServerId;
import dev.sam.common.identity.ServerIdentity;
import dev.sam.common.identity.ServerPublicKey;

/**
 * TrustManager del cliente SAM (PROTOCOLO.md 3.2 a 3.4): <b>no usa PKIX</b> (no hay autoridades de
 * certificación). Durante el handshake exige ALPN {@code sam/1}, clave Ed25519 y un server_id
 * válido en el certificado, y registra la identidad presentada. La decisión de confianza (pin,
 * primera conexión, rotación) la toma después el almacén de pins, antes de enviar credenciales.
 *
 * <p>Solo funciona con {@link SSLEngine} (el SslHandler de Netty); el resto de las variantes
 * rechaza todo.
 */
public final class ServerCertificateObserver extends X509ExtendedTrustManager {

    /** La identidad que presentó el servidor en este handshake. */
    public record ObservedServer(ServerId serverId, ServerPublicKey publicKey, X509Certificate certificate) {
    }

    private final AtomicReference<ObservedServer> observed = new AtomicReference<>();

    public Optional<ObservedServer> observed() {
        return Optional.ofNullable(observed.get());
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("El servidor no presentó certificado");
        }
        if (!SamTls.ALPN.equals(engine.getHandshakeApplicationProtocol())) {
            throw new CertificateException("El servidor no negoció ALPN " + SamTls.ALPN);
        }
        var leaf = chain[0];
        try {
            var publicKey = ServerPublicKey.fromSpki(leaf.getPublicKey().getEncoded());
            observed.set(new ObservedServer(ServerIdentity.serverIdOf(leaf), publicKey, leaf));
        } catch (IllegalArgumentException e) {
            throw new CertificateException("Certificado de servidor no válido para SAM: " + e.getMessage(), e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        throw new CertificateException("SAM solo valida certificados a través de SSLEngine");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("SAM solo valida certificados a través de SSLEngine");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        throw new CertificateException("SAM no usa certificados de cliente");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        throw new CertificateException("SAM no usa certificados de cliente");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("SAM no usa certificados de cliente");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
