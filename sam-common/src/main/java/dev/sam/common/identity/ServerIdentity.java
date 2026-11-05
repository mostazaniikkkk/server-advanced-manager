package dev.sam.common.identity;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Identidad del servidor (RS-NET-01, PROTOCOLO.md 3.1): par Ed25519, {@code server_id} aleatorio
 * y certificado X.509 autofirmado con {@code CN=SAM Server, SERIALNUMBER=<server_id en hex>}.
 *
 * <p>Las claves y la firma son las de la JDK; BouncyCastle solo arma la estructura X.509.
 */
public final class ServerIdentity {

    public static final String COMMON_NAME = "SAM Server";
    static final Duration BACKDATE = Duration.ofHours(1);
    static final Duration VALIDITY = Duration.ofDays(3650);
    private static final String ALGORITHM = "Ed25519";

    private final ServerId serverId;
    private final X509Certificate certificate;
    private final PrivateKey privateKey;
    private final ServerPublicKey publicKey;

    private ServerIdentity(ServerId serverId, X509Certificate certificate, PrivateKey privateKey) {
        this.serverId = serverId;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.publicKey = ServerPublicKey.fromSpki(certificate.getPublicKey().getEncoded());
    }

    /** Genera una identidad nueva (primer arranque del servidor). */
    public static ServerIdentity generate(SecureRandom random, Instant now) {
        var idBytes = new byte[ServerId.LENGTH];
        random.nextBytes(idBytes);
        var serverId = ServerId.of(idBytes);
        try {
            var generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(255, random);
            var keyPair = generator.generateKeyPair();
            var subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, COMMON_NAME)
                .addRDN(BCStyle.SERIALNUMBER, serverId.hex().toUpperCase())
                .build();
            var builder = new JcaX509v3CertificateBuilder(subject, new BigInteger(128, random).setBit(127),
                Date.from(now.minus(BACKDATE)), Date.from(now.plus(VALIDITY)), subject, keyPair.getPublic())
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            var holder = builder.build(new JcaContentSignerBuilder(ALGORITHM).build(keyPair.getPrivate()));
            var certificate = new JcaX509CertificateConverter().getCertificate(holder);
            return new ServerIdentity(serverId, certificate, keyPair.getPrivate());
        } catch (GeneralSecurityException | OperatorCreationException | CertIOException e) {
            throw new IllegalStateException("No se pudo generar la identidad del servidor", e);
        }
    }

    /**
     * Reconstruye una identidad guardada.
     *
     * @throws IllegalArgumentException si el certificado no tiene un server_id válido o la clave
     *                                  privada no corresponde a su clave pública
     */
    public static ServerIdentity of(X509Certificate certificate, PrivateKey privateKey) {
        var serverId = serverIdOf(certificate);
        if (!keysMatch(certificate, privateKey)) {
            throw new IllegalArgumentException("La clave privada no corresponde al certificado del servidor");
        }
        return new ServerIdentity(serverId, certificate, privateKey);
    }

    /**
     * El server_id que declara un certificado: su único {@code SERIALNUMBER} del Subject.
     *
     * @throws IllegalArgumentException si falta, hay más de uno o no son 32 dígitos hex
     */
    public static ServerId serverIdOf(X509Certificate certificate) {
        X500Name subject;
        try {
            subject = new JcaX509CertificateHolder(certificate).getSubject();
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Certificado ilegible: no se puede leer su server_id", e);
        }
        var serials = subject.getRDNs(BCStyle.SERIALNUMBER);
        if (serials.length != 1) {
            throw new IllegalArgumentException("El certificado debe declarar exactamente un server_id (SERIALNUMBER)");
        }
        return ServerId.fromHex(serials[0].getFirst().getValue().toString().toLowerCase());
    }

    private static boolean keysMatch(X509Certificate certificate, PrivateKey privateKey) {
        try {
            var challenge = new byte[] {'S', 'A', 'M'};
            var signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(challenge);
            var signature = signer.sign();
            var verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public ServerId serverId() {
        return serverId;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public ServerPublicKey publicKey() {
        return publicKey;
    }
}
