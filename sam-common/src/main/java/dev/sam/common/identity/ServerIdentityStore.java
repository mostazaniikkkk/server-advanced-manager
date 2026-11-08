package dev.sam.common.identity;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;

/**
 * Guarda la identidad del servidor en un PKCS12 cifrado con la passphrase (RS-NET-02,
 * PROTOCOLO.md 3.1).
 *
 * <p><b>Nunca regenera sobre un archivo existente</b>: una identidad nueva cambiaría la clave del
 * servidor para todos los jugadores. Ante passphrase incorrecta, archivo dañado o sin la entrada
 * esperada, falla cerrado con {@link IllegalStateException} y deja el archivo intacto.
 */
public final class ServerIdentityStore {

    static final String ALIAS = "sam-server-identity";

    /** @param created si se generó en esta llamada (primer arranque) */
    public record LoadResult(ServerIdentity identity, boolean created) {
    }

    private ServerIdentityStore() {
    }

    /**
     * Carga la identidad o, si el archivo no existe, la genera y la guarda. Borra la passphrase
     * recibida al terminar.
     */
    public static LoadResult loadOrCreate(Path file, char[] passphrase, SecureRandom random, Instant now) {
        try {
            if (passphrase.length == 0) {
                throw new IllegalArgumentException("La passphrase de la identidad del servidor no puede estar vacía");
            }
            if (Files.exists(file)) {
                return new LoadResult(load(file, passphrase), false);
            }
            var identity = ServerIdentity.generate(random, now);
            save(file, identity, passphrase);
            return new LoadResult(identity, true);
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    private static ServerIdentity load(Path file, char[] passphrase) {
        KeyStore keyStore;
        try (var in = Files.newInputStream(file)) {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(in, passphrase);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo abrir " + file.getFileName()
                + ": passphrase incorrecta o archivo dañado. No se genera una identidad nueva.", e);
        }
        try {
            // getEntry con contraseña lanza UnsupportedOperationException ante un certificado suelto:
            // primero se exige que el alias sea una entrada de clave. Una PrivateKeyEntry de PKCS12
            // siempre trae su certificado X.509; una clave simétrica no es PrivateKeyEntry.
            if (!keyStore.isKeyEntry(ALIAS)
                    || !(keyStore.getEntry(ALIAS, new KeyStore.PasswordProtection(passphrase))
                        instanceof KeyStore.PrivateKeyEntry privateKeyEntry)) {
                throw new IllegalStateException(file.getFileName() + " no contiene la identidad del servidor");
            }
            return ServerIdentity.of((X509Certificate) privateKeyEntry.getCertificate(), privateKeyEntry.getPrivateKey());
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException(file.getFileName() + " no contiene una identidad de servidor válida", e);
        }
    }

    private static void save(Path file, ServerIdentity identity, char[] passphrase) {
        try {
            var dir = file.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            var keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry(ALIAS, identity.privateKey(), passphrase, new Certificate[] {identity.certificate()});
            // Escritura atómica y solo para el dueño desde que nace (RF-CFG-10): un corte a mitad nunca deja
            // una identidad a medias en su lugar. Solo se llama cuando no existe (loadOrCreate)
            var out = new java.io.ByteArrayOutputStream();
            keyStore.store(out, passphrase);
            dev.sam.common.config.SecureFiles.write(file, out.toByteArray());
        } catch (IOException e) {
            throw new UncheckedIOException("No se pudo guardar la identidad del servidor en " + file, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo cifrar la identidad del servidor", e);
        }
    }
}
