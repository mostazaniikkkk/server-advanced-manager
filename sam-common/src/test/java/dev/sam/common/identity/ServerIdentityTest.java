package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** RS-NET-01 / PROTOCOLO.md 3.1 (P-05): certificado de identidad del servidor. */
class ServerIdentityTest {

    private static final Instant AHORA = Instant.parse("2026-11-05T12:00:00Z");
    private static ServerIdentity identidad;

    @BeforeAll
    static void generar() {
        identidad = ServerIdentity.generate(new SecureRandom(), AHORA);
    }

    @Test
    void elCertificadoEsEd25519YEstaAutofirmado() throws Exception {
        var cert = identidad.certificate();
        assertThat(cert.getSigAlgName()).isEqualTo("Ed25519");
        cert.verify(cert.getPublicKey());
        assertThat(cert.getIssuerX500Principal()).isEqualTo(cert.getSubjectX500Principal());
    }

    @Test
    void elSubjectLlevaElServerIdComoSerialNumber() {
        // RFC 2253 muestra los OID "no conocidos" como DER en hex: se le da el nombre de 2.5.4.5
        var subject = identidad.certificate().getSubjectX500Principal()
            .getName(javax.security.auth.x500.X500Principal.RFC2253, java.util.Map.of("2.5.4.5", "SERIALNUMBER"));
        assertThat(subject).contains("CN=SAM Server").contains("SERIALNUMBER=" + identidad.serverId().hex().toUpperCase());
        assertThat(ServerIdentity.serverIdOf(identidad.certificate())).isEqualTo(identidad.serverId());
    }

    @Test
    void laClavePublicaEsLaDelCertificado() {
        assertThat(identidad.publicKey().spki()).isEqualTo(identidad.certificate().getPublicKey().getEncoded());
        assertThat(identidad.publicKey().pin()).isEqualTo(Pin.ofSpki(identidad.certificate().getPublicKey().getEncoded()));
    }

    @Test
    void laClavePrivadaCorrespondeALaPublica() throws Exception {
        var firmador = Signature.getInstance("Ed25519");
        firmador.initSign(identidad.privateKey());
        firmador.update(new byte[] {1, 2, 3});
        assertThat(identidad.publicKey().verify(new byte[] {1, 2, 3}, firmador.sign())).isTrue();
    }

    @Test
    void noEsUnaCaYSoloSirveParaFirmar() {
        var cert = identidad.certificate();
        assertThat(cert.getBasicConstraints()).isEqualTo(-1);
        assertThat(cert.getKeyUsage()).isNotNull();
        assertThat(cert.getKeyUsage()[0]).as("digitalSignature").isTrue();
        assertThat(cert.getKeyUsage()[5]).as("keyCertSign").isFalse();
        assertThat(cert.getCriticalExtensionOIDs()).contains("2.5.29.19", "2.5.29.15");
    }

    @Test
    void esValidoDesdeUnaHoraAntesYDuranteDiezAnos() {
        var cert = identidad.certificate();
        assertThat(cert.getNotBefore().toInstant()).isEqualTo(AHORA.minus(Duration.ofHours(1)));
        assertThat(cert.getNotAfter().toInstant()).isEqualTo(AHORA.plus(Duration.ofDays(3650)));
    }

    @Test
    void elNumeroDeSerieEsPositivoYDe128Bits() {
        var serie = identidad.certificate().getSerialNumber();
        assertThat(serie.signum()).isPositive();
        assertThat(serie.bitLength()).isLessThanOrEqualTo(128).isGreaterThan(64);
    }

    @Test
    void dosIdentidadesGeneradasSonDistintas() {
        var otra = ServerIdentity.generate(new SecureRandom(), AHORA);
        assertThat(otra.serverId()).isNotEqualTo(identidad.serverId());
        assertThat(otra.publicKey()).isNotEqualTo(identidad.publicKey());
        assertThat(otra.certificate().getSerialNumber()).isNotEqualTo(identidad.certificate().getSerialNumber());
    }

    @Test
    void reconstruirLaIdentidadDesdeSusPartesConservaTodo() {
        var copia = ServerIdentity.of(identidad.certificate(), identidad.privateKey());
        assertThat(copia.serverId()).isEqualTo(identidad.serverId());
        assertThat(copia.publicKey()).isEqualTo(identidad.publicKey());
    }

    @Test
    void usaElAzarQueSeLePasa() throws Exception {
        // Con el mismo generador sembrado, todo (server_id, claves, número de serie, firma) se repite
        var a = ServerIdentity.generate(sembrado(), AHORA);
        var b = ServerIdentity.generate(sembrado(), AHORA);
        assertThat(b.serverId()).isEqualTo(a.serverId());
        assertThat(b.publicKey()).isEqualTo(a.publicKey());
        assertThat(b.certificate().getEncoded()).isEqualTo(a.certificate().getEncoded());
    }

    @Test
    void reconstruirConUnaClavePrivadaDeOtroAlgoritmoFalla() throws Exception {
        var rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
        assertThatThrownBy(() -> ServerIdentity.of(identidad.certificate(), rsa))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("no corresponde");
    }

    private static SecureRandom sembrado() throws Exception {
        var random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] {4, 2});
        return random;
    }

    @Test
    void reconstruirConUnaClavePrivadaQueNoCorrespondeFalla() {
        var otra = ServerIdentity.generate(new SecureRandom(), AHORA);
        assertThatThrownBy(() -> ServerIdentity.of(identidad.certificate(), otra.privateKey()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("no corresponde");
    }

    // ===== serverIdOf con certificados ajenos =====

    @ParameterizedTest(name = "rechaza el subject \"{0}\"")
    @ValueSource(strings = {
        "CN=SAM Server",                                                    // sin serialNumber
        "CN=SAM Server,SERIALNUMBER=zz",                                    // hex inválido
        "CN=SAM Server,SERIALNUMBER=0000000000000000000000000000000",       // 31 dígitos
        "CN=SAM Server,SERIALNUMBER=00000000000000000000000000000001,SERIALNUMBER=00000000000000000000000000000002",
    })
    void serverIdOfRechazaSubjectsSinUnServerIdValido(String subject) throws Exception {
        var cert = certificadoCon(subject);
        assertThatThrownBy(() -> ServerIdentity.serverIdOf(cert))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("server_id");
    }

    @Test
    void serverIdOfAceptaMayusculasYMinusculasEnElHex() throws Exception {
        var cert = certificadoCon("CN=SAM Server,SERIALNUMBER=0000000000000000000000000000ABcd");
        assertThat(ServerIdentity.serverIdOf(cert)).isEqualTo(ServerId.fromHex("0000000000000000000000000000abcd"));
    }

    private static X509Certificate certificadoCon(String subject) throws Exception {
        var par = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var nombre = new X500Name(subject);
        var builder = new JcaX509v3CertificateBuilder(nombre, BigInteger.ONE, Date.from(AHORA),
            Date.from(AHORA.plus(Duration.ofDays(1))), nombre, par.getPublic());
        var holder = builder.build(new JcaContentSignerBuilder("Ed25519").build(par.getPrivate()));
        return new JcaX509CertificateConverter().getCertificate(holder);
    }
}
