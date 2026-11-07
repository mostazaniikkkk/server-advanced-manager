package dev.sam.signer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import dev.sam.common.scripts.SigningPublicKey;

/**
 * La clave de firma del operador en disco (RS-SIG-07): PKCS#8 cifrado con passphrase (PBES2:
 * PBKDF2-HMAC-SHA256 + AES-256-CBC), en PEM, legible también por OpenSSL. La pública va aparte, en el
 * formato del trust store del servidor.
 */
class SigningKeyFileTest {

    private static final char[] FRASE = "una frase larga de prueba".toCharArray();

    @Test
    void laClaveCifradaSeAbreConSuPassphrase() {
        var nueva = SigningKeyFile.generate(new SecureRandom());
        var pem = SigningKeyFile.encrypt(nueva, FRASE, new SecureRandom(), 1000);
        assertThat(pem).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----\n").endsWith("-----END ENCRYPTED PRIVATE KEY-----\n");
        var abierta = SigningKeyFile.decrypt(pem, FRASE);
        assertThat(abierta.publicKeyRaw()).isEqualTo(nueva.publicKeyRaw());
        // Lo que se firma con la abierta lo verifica la pública de la original
        var firma = abierta.sign("hola".getBytes(StandardCharsets.UTF_8));
        assertThat(SigningPublicKey.of(nueva.publicKeyRaw()).verify("hola".getBytes(StandardCharsets.UTF_8), firma)).isTrue();
    }

    @Test
    void esPkcs8CifradoConPbes2YAes256() throws Exception {
        var clave = SigningKeyFile.generate(new SecureRandom());
        var pem = SigningKeyFile.encrypt(clave, FRASE, new SecureRandom(), 1000);
        var body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        // Interoperabilidad: la JDK, sola, lo descifra y obtiene el PKCS#8 de Ed25519
        var jdkInfo = new javax.crypto.EncryptedPrivateKeyInfo(Base64.getDecoder().decode(body));
        var cipher = javax.crypto.Cipher.getInstance(jdkInfo.getAlgName());
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.SecretKeyFactory.getInstance(jdkInfo.getAlgName())
            .generateSecret(new javax.crypto.spec.PBEKeySpec(FRASE)), jdkInfo.getAlgParameters());
        var pkcs8 = cipher.doFinal(jdkInfo.getEncryptedData());
        assertThat(java.security.KeyFactory.getInstance("Ed25519").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8))
            .getAlgorithm()).isEqualTo("EdDSA");
        assertThat(java.util.Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length)).isEqualTo(clave.seed());
        // La estructura: EncryptedPrivateKeyInfo con PBES2, AES-256-CBC y PBKDF2-HMAC-SHA256
        var info = new org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo(Base64.getDecoder().decode(body));
        assertThat(info.getEncryptionAlgorithm().getAlgorithm().getId()).isEqualTo("1.2.840.113549.1.5.13");
        var parametros = org.bouncycastle.asn1.pkcs.PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
        assertThat(parametros.getEncryptionScheme().getAlgorithm().getId()).isEqualTo("2.16.840.1.101.3.4.1.42");
        var kdf = org.bouncycastle.asn1.pkcs.PBKDF2Params.getInstance(parametros.getKeyDerivationFunc().getParameters());
        assertThat(kdf.getIterationCount().intValue()).isEqualTo(1000);
        assertThat(kdf.getPrf().getAlgorithm().getId()).isEqualTo("1.2.840.113549.2.9");
        // Las líneas del PEM son de 64 caracteres, como en OpenSSL
        assertThat(pem.lines().filter(l -> !l.startsWith("-----"))).allMatch(l -> l.length() <= 64);
        assertThat(pem.lines().filter(l -> !l.startsWith("-----")).findFirst().orElseThrow()).hasSize(64);
    }

    @Test
    void unaPassphraseEquivocadaOUnArchivoMaloNoAbre() {
        var pem = SigningKeyFile.encrypt(SigningKeyFile.generate(new SecureRandom()), FRASE, new SecureRandom(), 1000);
        assertThatThrownBy(() -> SigningKeyFile.decrypt(pem, "otra".toCharArray())).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("passphrase incorrecta o archivo de clave dañado");
        assertThatThrownBy(() -> SigningKeyFile.decrypt("no es un pem", FRASE)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("passphrase incorrecta o archivo de clave dañado");
        assertThatThrownBy(() -> SigningKeyFile.decrypt("-----BEGIN ENCRYPTED PRIVATE KEY-----\n%%%\n-----END ENCRYPTED PRIVATE KEY-----\n",
            FRASE)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void cadaCifradoUsaSalYNuevoIv() {
        var clave = SigningKeyFile.generate(new SecureRandom());
        assertThat(SigningKeyFile.encrypt(clave, FRASE, new SecureRandom(), 1000))
            .isNotEqualTo(SigningKeyFile.encrypt(clave, FRASE, new SecureRandom(), 1000));
        assertThat(SigningKeyFile.ITERATIONS).isEqualTo(600_000);
    }

    @Test
    void laPublicaVaEnElFormatoDelTrustStore() {
        var clave = SigningKeyFile.generate(new SecureRandom());
        var pub = SigningKeyFile.publicFile(clave, "Steve");
        var lineas = pub.lines().toList();
        assertThat(lineas.get(0)).isEqualTo("# Clave de firma de scripts de SAM: Steve (key_id "
            + SigningPublicKey.of(clave.publicKeyRaw()).keyId().hex() + ")");
        assertThat(Base64.getDecoder().decode(lineas.get(1))).isEqualTo(clave.publicKeyRaw());
        assertThat(lineas).hasSize(2);
    }

    @Test
    void unaPassphraseCortaNoSeAcepta() {
        assertThatThrownBy(() -> SigningKeyFile.encrypt(SigningKeyFile.generate(new SecureRandom()), "corta".toCharArray(),
            new SecureRandom(), 1000)).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("la passphrase debe tener al menos 12 caracteres");
        assertThat(SigningKeyFile.encrypt(SigningKeyFile.generate(new SecureRandom()), "123456789012".toCharArray(),
            new SecureRandom(), 1000)).isNotBlank();
    }
}
