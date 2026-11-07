package dev.sam.signer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import dev.sam.common.crypto.Ed25519PrivateKey;
import dev.sam.common.scripts.SigningPublicKey;

/**
 * La clave de firma del operador en disco (RS-SIG-07): PKCS#8 de Ed25519 (RFC 8410) cifrado con PBES2
 * (PBKDF2-HMAC-SHA256 y AES-256-CBC, RFC 8018), en PEM ({@code ENCRYPTED PRIVATE KEY}): el formato
 * estándar que abren OpenSSL y la JDK. La derivación y el cifrado son de la JDK; BouncyCastle solo arma y
 * lee la estructura ASN.1. Al leer se acepta únicamente ese esquema.
 */
final class SigningKeyFile {

    /** PBKDF2-HMAC-SHA256: lo que recomienda OWASP (2023). */
    static final int ITERATIONS = 600_000;
    static final int MIN_PASSPHRASE = 12;
    private static final int AES_KEY_BYTES = 32;
    private static final AlgorithmIdentifier HMAC_SHA256 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256,
        DERNull.INSTANCE);
    /** PrivateKeyInfo de Ed25519 (RFC 8410) hasta la semilla: versión 0, OID 1.3.101.112, OCTET STRING. */
    private static final byte[] PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b657004220420");
    private static final String BEGIN = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    private static final String END = "-----END ENCRYPTED PRIVATE KEY-----";
    private static final String DAMAGED = "passphrase incorrecta o archivo de clave dañado";
    private static final java.util.regex.Pattern PEM = java.util.regex.Pattern.compile(
        java.util.regex.Pattern.quote(BEGIN) + "([^-]*)" + java.util.regex.Pattern.quote(END));

    /** Una clave de firma: la semilla Ed25519 (32 bytes). */
    record SigningKey(byte[] seed) {

        SigningKey {
            seed = seed.clone();
        }

        @Override
        public byte[] seed() {
            return seed.clone();
        }

        byte[] publicKeyRaw() {
            return Ed25519PrivateKey.fromSeed(seed).publicKeyRaw();
        }

        byte[] sign(byte[] message) {
            return Ed25519PrivateKey.fromSeed(seed).sign(message);
        }

        Ed25519PrivateKey privateKey() {
            return Ed25519PrivateKey.fromSeed(seed);
        }
    }

    private SigningKeyFile() {
    }

    static SigningKey generate(SecureRandom random) {
        var seed = new byte[Ed25519PrivateKey.SEED_LENGTH];
        random.nextBytes(seed);
        return new SigningKey(seed);
    }

    static String encrypt(SigningKey key, char[] passphrase, SecureRandom random, int iterations) {
        if (passphrase.length < MIN_PASSPHRASE) {
            throw new IllegalArgumentException("la passphrase debe tener al menos " + MIN_PASSPHRASE + " caracteres");
        }
        var plain = pkcs8(key.seed());
        try {
            return encryptBytes(plain, passphrase, random, iterations);
        } finally {
            Secrets.wipe(plain);
        }
    }

    /** Cifra cualquier contenido como si fuera el PKCS#8 (las pruebas arman archivos con contenido inválido). */
    static String encryptBytes(byte[] plain, char[] passphrase, SecureRandom random, int iterations) {
        var salt = new byte[16];
        var iv = new byte[16];
        random.nextBytes(salt);
        random.nextBytes(iv);
        try {
            var cipher = aes(Cipher.ENCRYPT_MODE, passphrase, salt, iterations, iv);
            var scheme = new PBES2Parameters(
                new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterations, AES_KEY_BYTES, HMAC_SHA256)),
                new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CBC, new DEROctetString(iv)));
            var info = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, scheme), cipher.doFinal(plain));
            return BEGIN + "\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(info.getEncoded())
                + "\n" + END + "\n";
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("PBKDF2 y AES siempre existen en la JDK", e);
        }
    }

    static SigningKey decrypt(String pem, char[] passphrase) {
        try {
            // Sin las dos marcas no hay coincidencia: NoSuchElementException, y termina en DAMAGED como el resto
            var body = PEM.matcher(pem).results().findFirst().orElseThrow().group(1);
            var info = EncryptedPrivateKeyInfo.getInstance(Base64.getMimeDecoder().decode(body));
            var algorithm = info.getEncryptionAlgorithm();
            if (!algorithm.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBES2)) {
                throw new IllegalArgumentException(DAMAGED);
            }
            var scheme = PBES2Parameters.getInstance(algorithm.getParameters());
            var kdf = PBKDF2Params.getInstance(scheme.getKeyDerivationFunc().getParameters());
            if (!scheme.getKeyDerivationFunc().getAlgorithm().equals(PKCSObjectIdentifiers.id_PBKDF2)
                    || !kdf.getPrf().getAlgorithm().equals(PKCSObjectIdentifiers.id_hmacWithSHA256)
                    || !scheme.getEncryptionScheme().getAlgorithm().equals(NISTObjectIdentifiers.id_aes256_CBC)) {
                throw new IllegalArgumentException(DAMAGED);
            }
            var iv = ASN1OctetString.getInstance(scheme.getEncryptionScheme().getParameters()).getOctets();
            var plain = aes(Cipher.DECRYPT_MODE, passphrase, kdf.getSalt(), kdf.getIterationCount().intValueExact(), iv)
                .doFinal(info.getEncryptedData());
            if (plain.length != PKCS8_PREFIX.length + Ed25519PrivateKey.SEED_LENGTH
                    || !MessageDigest.isEqual(Arrays.copyOf(plain, PKCS8_PREFIX.length), PKCS8_PREFIX)) {
                throw new IllegalArgumentException(DAMAGED);
            }
            return new SigningKey(Arrays.copyOfRange(plain, PKCS8_PREFIX.length, plain.length));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException(DAMAGED, e);
        }
    }

    /** El {@code .pub} para {@code config/sam/keys/trusted/} del servidor. */
    static String publicFile(SigningKey key, String name) {
        var pub = SigningPublicKey.of(key.publicKeyRaw());
        return "# Clave de firma de scripts de SAM: " + name + " (key_id " + pub.keyId().hex() + ")\n"
            + Base64.getEncoder().encodeToString(key.publicKeyRaw()) + "\n";
    }

    private static Cipher aes(int mode, char[] passphrase, byte[] salt, int iterations, byte[] iv) throws GeneralSecurityException {
        var derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(new PBEKeySpec(passphrase, salt, iterations, AES_KEY_BYTES * 8)).getEncoded();
        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, new SecretKeySpec(derived, "AES"), new IvParameterSpec(iv));
        Secrets.wipe(derived);
        return cipher;
    }

    private static byte[] pkcs8(byte[] seed) {
        var out = Arrays.copyOf(PKCS8_PREFIX, PKCS8_PREFIX.length + seed.length);
        System.arraycopy(seed, 0, out, PKCS8_PREFIX.length, seed.length);
        return out;
    }
}
