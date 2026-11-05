package dev.sam.common.net.tls;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.sam.common.identity.ServerIdentity;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;

/**
 * TLS 1.3 de SAM (RS-NET-05, PROTOCOLO.md 3.2) con el certificado Ed25519 del servidor: también es
 * la validación 1 de la fase 0 (soporte de Ed25519 en TLS 1.3 con la JSSE de la JDK).
 *
 * <p>Dos SslHandler de Netty (el mismo handler que irá en producción) conectados en memoria.
 */
class SamTlsTest {

    private static ServerIdentity identidad;

    @BeforeAll
    static void identidad() {
        identidad = ServerIdentity.generate(new SecureRandom(), Instant.now());
    }

    @Test
    void handshakeTls13ConEd25519AlpnSamYSuiteDelPerfil() {
        var observador = new ServerCertificateObserver();
        var par = Par.de(SamTls.serverEngine(identidad), SamTls.clientEngine(observador, "127.0.0.1", 25567));

        assertThat(par.completar()).as("handshake completo").isTrue();
        var sesion = par.cliente.engine().getSession();
        assertThat(sesion.getProtocol()).isEqualTo("TLSv1.3");
        assertThat(SamTls.CIPHER_SUITES).contains(sesion.getCipherSuite());
        assertThat(par.cliente.engine().getApplicationProtocol()).isEqualTo(SamTls.ALPN);
        assertThat(par.servidor.engine().getApplicationProtocol()).isEqualTo(SamTls.ALPN);
    }

    @Test
    void elClienteRegistraLaIdentidadPresentadaParaElPinning() {
        var observador = new ServerCertificateObserver();
        var par = Par.de(SamTls.serverEngine(identidad), SamTls.clientEngine(observador, "127.0.0.1", 25567));
        assertThat(par.completar()).isTrue();
        var visto = observador.observed().orElseThrow();
        assertThat(visto.serverId()).isEqualTo(identidad.serverId());
        assertThat(visto.publicKey()).isEqualTo(identidad.publicKey());
        assertThat(visto.certificate()).isEqualTo(identidad.certificate());
    }

    @Test
    void losDatosViajanCifradosEnAmbosSentidos() {
        var par = Par.de(SamTls.serverEngine(identidad), SamTls.clientEngine(new ServerCertificateObserver(), "127.0.0.1", 25567));
        assertThat(par.completar()).isTrue();
        var mensaje = "hola por TLS".getBytes(StandardCharsets.UTF_8);
        par.cliente.writeOutbound(Unpooled.wrappedBuffer(mensaje));
        var cifrado = par.transferir(par.cliente, par.servidor);
        assertThat(new String(cifrado, StandardCharsets.ISO_8859_1)).doesNotContain("hola por TLS");
        assertThat(leer(par.servidor)).isEqualTo(mensaje);
    }

    @Test
    void unClienteSinAlpnSamNoConecta() {
        var cliente = SamTls.clientEngine(new ServerCertificateObserver(), "127.0.0.1", 25567);
        var parametros = cliente.getSSLParameters();
        parametros.setApplicationProtocols(new String[] {"h2"});
        cliente.setSSLParameters(parametros);
        assertThat(Par.de(SamTls.serverEngine(identidad), cliente).completar()).isFalse();
    }

    @Test
    void unClienteTlsCualquieraSinAlpnEsDesconectadoTrasElHandshake() throws Exception {
        // Un cliente que no es SAM: acepta cualquier certificado y no ofrece ALPN. La JSSE no consulta
        // el selector sin la extensión, así que el handshake TLS termina: el servidor debe cerrar igual.
        var contexto = SSLContext.getInstance("TLSv1.3");
        contexto.init(null, new javax.net.ssl.TrustManager[] {new ConfiaEnTodo()}, null);
        var cliente = contexto.createSSLEngine("127.0.0.1", 25567);
        cliente.setUseClientMode(true);
        var par = new Par(new Lado(cliente), new Lado(SamTls.serverHandlers(identidad)));
        par.completar();
        assertThat(par.servidor.isOpen()).as("el servidor cierra la conexión sin ALPN sam/1").isFalse();
        par.cliente.writeOutbound(Unpooled.wrappedBuffer("dato".getBytes(StandardCharsets.UTF_8)));
        par.transferir(par.cliente, par.servidor);
        assertThat(leer(par.servidor)).isEmpty();
    }

    @Test
    void elHandlerDelServidorDejaPasarAUnClienteSam() {
        var par = new Par(new Lado(SamTls.clientEngine(new ServerCertificateObserver(), "127.0.0.1", 25567)),
            new Lado(SamTls.serverHandlers(identidad)));
        assertThat(par.completar()).isTrue();
        assertThat(par.servidor.isOpen()).isTrue();
        var mensaje = "hola".getBytes(StandardCharsets.UTF_8);
        par.cliente.writeOutbound(Unpooled.wrappedBuffer(mensaje));
        par.transferir(par.cliente, par.servidor);
        assertThat(leer(par.servidor)).isEqualTo(mensaje);
    }

    @Test
    void elGuardiaAlpnDejaPasarLosEventosQueNoSonDeTls() {
        var eventos = new java.util.ArrayList<Object>();
        var canal = new EmbeddedChannel(SamTls.serverHandlers(identidad)[1], new io.netty.channel.ChannelInboundHandlerAdapter() {
            @Override
            public void userEventTriggered(io.netty.channel.ChannelHandlerContext ctx, Object evento) {
                eventos.add(evento);
            }
        });
        canal.pipeline().fireUserEventTriggered("otro evento");
        assertThat(eventos).containsExactly("otro evento");
        assertThat(canal.isOpen()).isTrue();
    }

    @Test
    void unServidorQueNoNegociaAlpnSamSeRechazaAunqueSuCertificadoSeaValido() throws Exception {
        // Mismo certificado SAM, pero el servidor no negocia ALPN: el cliente debe rechazarlo solo
        var almacen = KeyStore.getInstance("PKCS12");
        almacen.load(null, null);
        almacen.setKeyEntry("k", identidad.privateKey(), new char[0], new Certificate[] {identidad.certificate()});
        var kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(almacen, new char[0]);
        var contexto = SSLContext.getInstance("TLSv1.3");
        contexto.init(kmf.getKeyManagers(), null, null);
        var servidor = contexto.createSSLEngine();
        servidor.setUseClientMode(false);
        var observador = new ServerCertificateObserver();
        assertThat(Par.de(servidor, SamTls.clientEngine(observador, "127.0.0.1", 25567)).completar()).isFalse();
        assertThat(observador.observed()).isEmpty();
    }

    @Test
    void elObservadorRechazaCadenasVaciasYTodoLoQueNoSeaUnServidorPorSSLEngine() {
        var observador = new ServerCertificateObserver();
        var engine = SamTls.clientEngine(observador, "127.0.0.1", 25567);
        var cadena = new X509Certificate[] {identidad.certificate()};
        assertThat(observador.getAcceptedIssuers()).isNotNull().isEmpty();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> observador.checkServerTrusted(new X509Certificate[0], "EdDSA", engine))
            .isInstanceOf(java.security.cert.CertificateException.class).hasMessageContaining("no presentó certificado");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> observador.checkServerTrusted(null, "EdDSA", engine))
            .isInstanceOf(java.security.cert.CertificateException.class).hasMessageContaining("no presentó certificado");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> observador.checkServerTrusted(cadena, "EdDSA"))
            .isInstanceOf(java.security.cert.CertificateException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> observador.checkServerTrusted(cadena, "EdDSA", (java.net.Socket) null))
            .isInstanceOf(java.security.cert.CertificateException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> observador.checkClientTrusted(cadena, "EdDSA", engine))
            .isInstanceOf(java.security.cert.CertificateException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> observador.checkClientTrusted(cadena, "EdDSA", (java.net.Socket) null))
            .isInstanceOf(java.security.cert.CertificateException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> observador.checkClientTrusted(cadena, "EdDSA"))
            .isInstanceOf(java.security.cert.CertificateException.class);
        assertThat(observador.observed()).isEmpty();
    }

    /** TrustManager de un cliente TLS genérico que acepta cualquier servidor (no es SAM). */
    private static final class ConfiaEnTodo extends javax.net.ssl.X509ExtendedTrustManager {
        @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) { }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, java.net.Socket s) { }
        @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) { }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, java.net.Socket s) { }
        @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    @Test
    void unClienteQueSoloOfreceTls12NoConecta() {
        var cliente = SamTls.clientEngine(new ServerCertificateObserver(), "127.0.0.1", 25567);
        cliente.setEnabledProtocols(new String[] {"TLSv1.2"});
        assertThat(Par.de(SamTls.serverEngine(identidad), cliente).completar()).isFalse();
    }

    @Test
    void elServidorSoloHabilitaTls13YLasSuitesDelPerfil() {
        var servidor = SamTls.serverEngine(identidad);
        assertThat(servidor.getEnabledProtocols()).containsExactly("TLSv1.3");
        assertThat(servidor.getEnabledCipherSuites()).containsExactlyInAnyOrderElementsOf(SamTls.CIPHER_SUITES);
        assertThat(servidor.getUseClientMode()).isFalse();
        assertThat(servidor.getNeedClientAuth()).isFalse();
    }

    @Test
    void unCertificadoSinServerIdSeRechaza() throws Exception {
        var par = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var observador = new ServerCertificateObserver();
        var resultado = Par.de(servidorCon(certificado("CN=Otro Servidor", par), par), SamTls.clientEngine(observador, "127.0.0.1", 25567));
        assertThat(resultado.completar()).isFalse();
        assertThat(observador.observed()).isEmpty();
    }

    @Test
    void unCertificadoQueNoEsEd25519SeRechaza() throws Exception {
        var generador = KeyPairGenerator.getInstance("EC");
        generador.initialize(new ECGenParameterSpec("secp256r1"));
        var par = generador.generateKeyPair();
        var observador = new ServerCertificateObserver();
        var cert = certificado("CN=SAM Server,SERIALNUMBER=00000000000000000000000000000001", par, "SHA256withECDSA");
        var resultado = Par.de(servidorCon(cert, par), SamTls.clientEngine(observador, "127.0.0.1", 25567));
        assertThat(resultado.completar()).isFalse();
        assertThat(observador.observed()).isEmpty();
    }

    // ===== Helpers =====

    private static SSLEngine servidorCon(X509Certificate cert, KeyPair par) throws Exception {
        var almacen = KeyStore.getInstance("PKCS12");
        almacen.load(null, null);
        almacen.setKeyEntry("k", par.getPrivate(), new char[0], new Certificate[] {cert});
        var kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(almacen, new char[0]);
        var contexto = SSLContext.getInstance("TLSv1.3");
        contexto.init(kmf.getKeyManagers(), null, null);
        var engine = contexto.createSSLEngine();
        engine.setUseClientMode(false);
        engine.setHandshakeApplicationProtocolSelector((e, ofrecidos) -> ofrecidos.contains(SamTls.ALPN) ? SamTls.ALPN : null);
        return engine;
    }

    private static X509Certificate certificado(String subject, KeyPair par) throws Exception {
        return certificado(subject, par, "Ed25519");
    }

    private static X509Certificate certificado(String subject, KeyPair par, String algoritmo) throws Exception {
        var nombre = new X500Name(subject);
        var ahora = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(nombre, BigInteger.ONE, Date.from(ahora.minus(Duration.ofHours(1))),
            Date.from(ahora.plus(Duration.ofDays(1))), nombre, par.getPublic());
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder(algoritmo).build(par.getPrivate())));
    }

    private static byte[] leer(EmbeddedChannel canal) {
        var salida = new java.io.ByteArrayOutputStream();
        Object msg;
        while ((msg = canal.readInbound()) != null) {
            var buf = (ByteBuf) msg;
            var bytes = new byte[buf.readableBytes()];
            buf.readBytes(bytes);
            buf.release();
            salida.writeBytes(bytes);
        }
        return salida.toByteArray();
    }

    /** Un cliente y un servidor con SslHandler, conectados en memoria. */
    private static final class Par {
        final Lado cliente;
        final Lado servidor;

        Par(Lado cliente, Lado servidor) {
            this.cliente = cliente;
            this.servidor = servidor;
        }

        static Par de(SSLEngine servidor, SSLEngine cliente) {
            return new Par(new Lado(cliente), new Lado(servidor));
        }

        /** Intercambia registros hasta que ambos terminan el handshake o alguno falla. */
        boolean completar() {
            for (int i = 0; i < 20; i++) {
                transferir(cliente, servidor);
                transferir(servidor, cliente);
                var c = cliente.handler.handshakeFuture();
                var s = servidor.handler.handshakeFuture();
                if (c.isDone() && s.isDone()) {
                    return c.isSuccess() && s.isSuccess();
                }
                if ((c.isDone() && !c.isSuccess()) || (s.isDone() && !s.isSuccess())) {
                    return false;
                }
            }
            return false;
        }

        /** Pasa los bytes salientes de un lado como entrantes del otro; devuelve lo transferido. */
        byte[] transferir(Lado desde, Lado hacia) {
            var todo = new java.io.ByteArrayOutputStream();
            Object msg;
            while ((msg = desde.readOutbound()) != null) {
                var buf = (ByteBuf) msg;
                var bytes = new byte[buf.readableBytes()];
                buf.readBytes(bytes);
                buf.release();
                todo.writeBytes(bytes);
                if (hacia.isOpen()) {
                    try {
                        hacia.writeInbound(Unpooled.wrappedBuffer(bytes));
                    } catch (RuntimeException ignorada) {
                        // un handshake fallido se refleja en handshakeFuture()
                    }
                }
            }
            return todo.toByteArray();
        }
    }

    private static final class Lado extends EmbeddedChannel {
        final SslHandler handler;

        Lado(SSLEngine engine) {
            this(new io.netty.channel.ChannelHandler[] {new SslHandler(engine)});
        }

        // Se guarda la referencia antes de agregarlos: si el handshake falla al instante (por
        // ejemplo, sin protocolo en común) Netty desarma el pipeline durante el constructor.
        Lado(io.netty.channel.ChannelHandler[] handlers) {
            super(handlers);
            this.handler = (SslHandler) handlers[0];
        }

        SSLEngine engine() {
            return handler.engine();
        }
    }
}
