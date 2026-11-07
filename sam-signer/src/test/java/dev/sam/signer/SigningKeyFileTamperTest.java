package dev.sam.signer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.function.UnaryOperator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.Test;

/**
 * Un archivo de clave que declara otro esquema que el de SAM se rechaza aunque descifraría igual: la
 * lectura no confía en lo que dice el archivo (PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC, y adentro el
 * PKCS#8 de Ed25519). Y {@link Secrets} borra de verdad.
 */
class SigningKeyFileTamperTest {

    private static final char[] FRASE = "una frase larga de prueba".toCharArray();
    private static final String OTRO_OID = "1.2.3.4";

    private static EncryptedPrivateKeyInfo info(String pem) {
        var body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return EncryptedPrivateKeyInfo.getInstance(Base64.getDecoder().decode(body));
    }

    private static String pem(EncryptedPrivateKeyInfo info) throws Exception {
        return "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(info.getEncoded())
            + "\n-----END ENCRYPTED PRIVATE KEY-----\n";
    }

    /** Reescribe los parámetros de PBES2 de una clave válida, sin tocar los datos cifrados. */
    private static String alterado(UnaryOperator<PBES2Parameters> cambio) throws Exception {
        var original = info(SigningKeyFile.encrypt(SigningKeyFile.generate(new SecureRandom()), FRASE, new SecureRandom(), 1000));
        var params = PBES2Parameters.getInstance(original.getEncryptionAlgorithm().getParameters());
        return pem(new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(original.getEncryptionAlgorithm().getAlgorithm(), cambio.apply(params)),
            original.getEncryptedData()));
    }

    private static void rechazado(String pem) {
        assertThatThrownBy(() -> SigningKeyFile.decrypt(pem, FRASE)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("passphrase incorrecta o archivo de clave dañado");
    }

    @Test
    void otroEsquemaDeclaradoSeRechazaAunqueDescifraraIgual() throws Exception {
        rechazado(alterado(p -> new PBES2Parameters(new KeyDerivationFunc(new ASN1ObjectIdentifier(OTRO_OID), p.getKeyDerivationFunc()
            .getParameters()), p.getEncryptionScheme())));
        rechazado(alterado(p -> {
            var kdf = PBKDF2Params.getInstance(p.getKeyDerivationFunc().getParameters());
            var sha1 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"), DERNull.INSTANCE);
            return new PBES2Parameters(new KeyDerivationFunc(p.getKeyDerivationFunc().getAlgorithm(),
                new PBKDF2Params(kdf.getSalt(), kdf.getIterationCount().intValue(), 32, sha1)), p.getEncryptionScheme());
        }));
        rechazado(alterado(p -> new PBES2Parameters(p.getKeyDerivationFunc(), new EncryptionScheme(
            new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2"), p.getEncryptionScheme().getParameters()))));
        var original = info(SigningKeyFile.encrypt(SigningKeyFile.generate(new SecureRandom()), FRASE, new SecureRandom(), 1000));
        rechazado(pem(new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(OTRO_OID),
            original.getEncryptionAlgorithm().getParameters()), original.getEncryptedData())));
    }

    @Test
    void adentroTieneQueEstarElPkcs8DeEd25519() {
        var prefijo = HexFormat.of().parseHex("302e020100300506032b657004220420");
        var bien = new byte[48];
        System.arraycopy(prefijo, 0, bien, 0, prefijo.length);
        assertThat(SigningKeyFile.decrypt(SigningKeyFile.encryptBytes(bien, FRASE, new SecureRandom(), 1000), FRASE).seed()).hasSize(32);
        var otroPrefijo = bien.clone();
        otroPrefijo[3] = 9;
        rechazado(SigningKeyFile.encryptBytes(otroPrefijo, FRASE, new SecureRandom(), 1000));
        rechazado(SigningKeyFile.encryptBytes(java.util.Arrays.copyOf(bien, 47), FRASE, new SecureRandom(), 1000));
        rechazado(SigningKeyFile.encryptBytes(java.util.Arrays.copyOf(bien, 49), FRASE, new SecureRandom(), 1000));
    }

    @Test
    void elPemTieneQueTenerSusDosMarcas() {
        var pem = SigningKeyFile.encrypt(SigningKeyFile.generate(new SecureRandom()), FRASE, new SecureRandom(), 1000);
        rechazado(pem.replace("-----END ENCRYPTED PRIVATE KEY-----", ""));
        rechazado(pem.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", ""));
        // Con texto alrededor (como al copiar de un correo) se lee igual
        assertThat(SigningKeyFile.decrypt("hola\n" + pem + "chau", FRASE).seed()).hasSize(32);
    }

    @Test
    void cadaClaveYCadaCifradoSonDistintos() {
        var a = SigningKeyFile.generate(new SecureRandom());
        assertThat(SigningKeyFile.generate(new SecureRandom()).seed()).isNotEqualTo(a.seed());
        var uno = PBES2Parameters.getInstance(info(SigningKeyFile.encrypt(a, FRASE, new SecureRandom(), 1000))
            .getEncryptionAlgorithm().getParameters());
        var dos = PBES2Parameters.getInstance(info(SigningKeyFile.encrypt(a, FRASE, new SecureRandom(), 1000))
            .getEncryptionAlgorithm().getParameters());
        assertThat(PBKDF2Params.getInstance(uno.getKeyDerivationFunc().getParameters()).getSalt())
            .isNotEqualTo(PBKDF2Params.getInstance(dos.getKeyDerivationFunc().getParameters()).getSalt());
        assertThat(uno.getEncryptionScheme().getParameters()).isNotEqualTo(dos.getEncryptionScheme().getParameters());
    }

    @Test
    void secretsBorraBytesYCaracteres() {
        var bytes = "secreto".getBytes(StandardCharsets.UTF_8);
        var otros = new byte[] {1, 2};
        var chars = "frase".toCharArray();
        Secrets.wipe(bytes, otros);
        Secrets.wipe(chars);
        assertThat(bytes).containsOnly(0);
        assertThat(otros).containsOnly(0);
        assertThat(chars).containsOnly('\0');
    }
}
