package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * RS-NET-02 / PROTOCOLO.md 3.1: la identidad se genera una vez y se guarda en un PKCS12 cifrado
 * con la passphrase. Regla crítica: nunca se regenera sobre un archivo existente (cambiaría la
 * clave del servidor para todos los jugadores): ante cualquier problema, falla cerrado.
 */
class ServerIdentityStoreTest {

    private static final Instant AHORA = Instant.parse("2026-11-05T12:00:00Z");
    private static final char[] CLAVE = "una passphrase larga".toCharArray();

    @TempDir
    Path dir;

    @Test
    void laPrimeraVezGeneraYGuardaLaIdentidad() {
        var archivo = dir.resolve("keys/identity.p12");
        var resultado = ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA);
        assertThat(resultado.created()).isTrue();
        assertThat(archivo).exists();
        assertThat(resultado.identity().certificate().getNotBefore().toInstant()).isBefore(AHORA);
    }

    @Test
    void laIdentidadSeGuardaSoloParaElDueno() throws Exception {
        try (var posix = com.google.common.jimfs.Jimfs.newFileSystem(com.google.common.jimfs.Configuration.unix().toBuilder()
                .setAttributeViews("basic", "owner", "posix").build())) {
            var archivo = posix.getPath("/srv/config/sam/keys/identity.p12");
            ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA);
            assertThat(java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(archivo)))
                .isEqualTo("rw-------");
            try (var archivos = Files.list(archivo.getParent())) {
                assertThat(archivos.map(p -> p.getFileName().toString())).containsExactly("identity.p12");
            }
        }
    }

    @Test
    void lasSiguientesVecesCargaLaMismaIdentidad() {
        var archivo = dir.resolve("identity.p12");
        var primera = ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA).identity();
        var segunda = ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA.plusSeconds(60));
        assertThat(segunda.created()).isFalse();
        assertThat(segunda.identity().serverId()).isEqualTo(primera.serverId());
        assertThat(segunda.identity().publicKey()).isEqualTo(primera.publicKey());
    }

    @Test
    void elArchivoEstaCifradoYNoAbreSinLaPassphrase() throws Exception {
        var archivo = dir.resolve("identity.p12");
        ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA);
        var almacen = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(archivo)) {
            assertThatThrownBy(() -> almacen.load(in, "otra".toCharArray())).isInstanceOf(java.io.IOException.class);
        }
    }

    @Test
    void unaPassphraseIncorrectaFallaCerradoSinTocarElArchivo() throws Exception {
        var archivo = dir.resolve("identity.p12");
        ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA);
        var antes = Files.readAllBytes(archivo);
        assertThatThrownBy(() -> ServerIdentityStore.loadOrCreate(archivo, "incorrecta".toCharArray(), new SecureRandom(), AHORA))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("passphrase");
        assertThat(Files.readAllBytes(archivo)).isEqualTo(antes);
    }

    @Test
    void unArchivoDanadoFallaCerradoSinRegenerar() throws Exception {
        var archivo = dir.resolve("identity.p12");
        Files.write(archivo, new byte[] {1, 2, 3, 4});
        assertThatThrownBy(() -> ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining(archivo.getFileName().toString());
        assertThat(Files.readAllBytes(archivo)).containsExactly(1, 2, 3, 4);
    }

    @Test
    void unAlmacenSinLaEntradaDeSamFallaCerrado() throws Exception {
        var archivo = dir.resolve("identity.p12");
        var vacio = KeyStore.getInstance("PKCS12");
        vacio.load(null, null);
        try (var out = Files.newOutputStream(archivo)) {
            vacio.store(out, CLAVE.clone());
        }
        assertThatThrownBy(() -> ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void unaEntradaConCertificadoPeroSinClavePrivadaFallaCerrado() throws Exception {
        var archivo = dir.resolve("identity.p12");
        var almacen = KeyStore.getInstance("PKCS12");
        almacen.load(null, null);
        almacen.setCertificateEntry(ServerIdentityStore.ALIAS, ServerIdentity.generate(new SecureRandom(), AHORA).certificate());
        try (var out = Files.newOutputStream(archivo)) {
            almacen.store(out, CLAVE.clone());
        }
        assertThatThrownBy(() -> ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void unaEntradaConClaveSimetricaYSinCertificadoFallaCerrado() throws Exception {
        var archivo = dir.resolve("identity.p12");
        var almacen = KeyStore.getInstance("PKCS12");
        almacen.load(null, null);
        var aes = javax.crypto.KeyGenerator.getInstance("AES").generateKey();
        almacen.setEntry(ServerIdentityStore.ALIAS, new KeyStore.SecretKeyEntry(aes), new KeyStore.PasswordProtection(CLAVE.clone()));
        try (var out = Files.newOutputStream(archivo)) {
            almacen.store(out, CLAVE.clone());
        }
        assertThatThrownBy(() -> ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void unaClaveYCertificadoQueNoSonDeSamFallaCerradoSinRegenerar() throws Exception {
        // Un identity.p12 reemplazado por otro PKCS12 válido (clave RSA, sin server_id): se abre, pero no es de SAM
        var archivo = dir.resolve("identity.p12");
        var rsa = java.security.KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        var par = rsa.generateKeyPair();
        var nombre = new org.bouncycastle.asn1.x500.X500Name("CN=otro servidor");
        var certificado = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
            new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(nombre, java.math.BigInteger.ONE,
                java.util.Date.from(AHORA), java.util.Date.from(AHORA.plusSeconds(3600)), nombre, par.getPublic())
                .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(par.getPrivate())));
        var almacen = KeyStore.getInstance("PKCS12");
        almacen.load(null, null);
        almacen.setKeyEntry(ServerIdentityStore.ALIAS, par.getPrivate(), CLAVE.clone(), new java.security.cert.Certificate[] {certificado});
        try (var out = Files.newOutputStream(archivo)) {
            almacen.store(out, CLAVE.clone());
        }
        var antes = Files.readAllBytes(archivo);
        assertThatThrownBy(() -> ServerIdentityStore.loadOrCreate(archivo, CLAVE.clone(), new SecureRandom(), AHORA))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("identity.p12 no contiene una identidad de servidor válida");
        assertThat(Files.readAllBytes(archivo)).isEqualTo(antes);
    }

    @Test
    void unaPassphraseVaciaSeRechaza() {
        assertThatThrownBy(() -> ServerIdentityStore.loadOrCreate(dir.resolve("identity.p12"), new char[0], new SecureRandom(), AHORA))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("passphrase");
        assertThat(dir.resolve("identity.p12")).doesNotExist();
    }

    @Test
    void alGuardarNoQuedanArchivosTemporales() throws Exception {
        ServerIdentityStore.loadOrCreate(dir.resolve("identity.p12"), CLAVE.clone(), new SecureRandom(), AHORA);
        try (var archivos = Files.list(dir)) {
            assertThat(archivos.map(p -> p.getFileName().toString())).containsExactly("identity.p12");
        }
    }

    @Test
    void borraLaPassphraseRecibida() {
        var clave = CLAVE.clone();
        ServerIdentityStore.loadOrCreate(dir.resolve("identity.p12"), clave, new SecureRandom(), AHORA);
        assertThat(clave).containsOnly('\0');
        var otra = CLAVE.clone();
        ServerIdentityStore.loadOrCreate(dir.resolve("identity.p12"), otra, new SecureRandom(), AHORA);
        assertThat(otra).containsOnly('\0');
    }
}
