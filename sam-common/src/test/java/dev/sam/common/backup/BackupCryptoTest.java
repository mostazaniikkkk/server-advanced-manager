package dev.sam.common.backup;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import org.junit.jupiter.api.Test;

/** RF-CFG-11 (H-16): respaldos cifrados por bloques con AES-256-GCM. */
class BackupCryptoTest {

    private static final byte[] KEY = new byte[32];
    private static final byte[] OTRA = new byte[32];

    static {
        Arrays.fill(KEY, (byte) 7);
        Arrays.fill(OTRA, (byte) 8);
    }

    private static byte[] datos(int n) {
        var b = new byte[n];
        new Random(n).nextBytes(b);
        return b;
    }

    private static byte[] sellar(byte[] claro) throws IOException {
        var out = new ByteArrayOutputStream();
        BackupCrypto.seal(new ByteArrayInputStream(claro), out, KEY, new SecureRandom());
        return out.toByteArray();
    }

    private static byte[] abrir(byte[] sellado, byte[] key) throws IOException {
        var out = new ByteArrayOutputStream();
        BackupCrypto.open(new ByteArrayInputStream(sellado), out, key);
        return out.toByteArray();
    }

    @Test
    void idaYVueltaConTamañosEnLosBordesDeBloque() throws Exception {
        for (var n : new int[] {0, 1, BackupCrypto.CHUNK - 1, BackupCrypto.CHUNK, BackupCrypto.CHUNK + 1, 3 * BackupCrypto.CHUNK + 5}) {
            var claro = datos(n);
            var sellado = sellar(claro);
            assertThat(abrir(sellado, KEY)).as("n=%d", n).isEqualTo(claro);
            var bloques = Math.max(1, (n + BackupCrypto.CHUNK - 1) / BackupCrypto.CHUNK);
            assertThat(sellado.length).as("n=%d", n).isEqualTo(6 + 12 + n + bloques * 16);
        }
    }

    @Test
    void empiezaConLaCabeceraYNoDejaElTextoEnClaro() throws Exception {
        var claro = "contraseñas y secretos del servidor".repeat(100).getBytes(StandardCharsets.UTF_8);
        var sellado = sellar(claro);
        assertThat(new String(sellado, 0, 6, StandardCharsets.US_ASCII)).isEqualTo("SAMBK1");
        assertThat(new String(sellado, StandardCharsets.ISO_8859_1)).doesNotContain("secretos");
    }

    @Test
    void dosSelladosDelMismoContenidoSonDistintos() throws Exception {
        var claro = datos(100);
        assertThat(sellar(claro)).isNotEqualTo(sellar(claro));
    }

    @Test
    void otraClaveNoAbre() throws Exception {
        var sellado = sellar(datos(10));
        assertThatThrownBy(() -> abrir(sellado, OTRA)).isInstanceOf(IOException.class).hasMessageContaining("clave");
    }

    @Test
    void cualquierByteCambiadoSeDetecta() throws Exception {
        var sellado = sellar(datos(2 * BackupCrypto.CHUNK + 10));
        for (var pos : new int[] {0, 5, 6, 17, 18, 100, BackupCrypto.CHUNK + 40, sellado.length - 1}) {
            var malo = sellado.clone();
            malo[pos] ^= 1;
            assertThatThrownBy(() -> abrir(malo, KEY)).as("pos=%d", pos).isInstanceOf(IOException.class);
        }
    }

    @Test
    void truncarQuitarOReordenarBloquesSeDetecta() throws Exception {
        var c = BackupCrypto.CHUNK;
        var sellado = sellar(datos(3 * c));
        var cab = 18;
        var bloque = c + 16;
        // Sin el último bloque: el anterior no está marcado como último
        assertThatThrownBy(() -> abrir(Arrays.copyOf(sellado, cab + 2 * bloque), KEY)).isInstanceOf(IOException.class);
        // Cortado a la mitad de un bloque
        assertThatThrownBy(() -> abrir(Arrays.copyOf(sellado, cab + bloque + 10), KEY)).isInstanceOf(IOException.class);
        // Solo la cabecera
        assertThatThrownBy(() -> abrir(Arrays.copyOf(sellado, cab), KEY)).isInstanceOf(IOException.class);
        // Bloques 1 y 2 intercambiados
        var cambiado = sellado.clone();
        System.arraycopy(sellado, cab + bloque, cambiado, cab, bloque);
        System.arraycopy(sellado, cab, cambiado, cab + bloque, bloque);
        assertThatThrownBy(() -> abrir(cambiado, KEY)).isInstanceOf(IOException.class);
        // Basura al final
        var largo = Arrays.copyOf(sellado, sellado.length + 3);
        assertThatThrownBy(() -> abrir(largo, KEY)).isInstanceOf(IOException.class);
    }

    @Test
    void elFormatoEsElDocumentado() throws Exception {
        // Descifrado independiente de los dos primeros bloques: nonce = base XOR número, AAD = cabecera + número + último
        var c = BackupCrypto.CHUNK;
        var claro = datos(c + 7);
        var sellado = sellar(claro);
        var base = Arrays.copyOfRange(sellado, 6, 18);
        for (var i = 0; i < 2; i++) {
            var nonce = base.clone();
            nonce[11] ^= (byte) i;
            var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(KEY, "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, nonce));
            var aad = java.nio.ByteBuffer.allocate(15).put("SAMBK1".getBytes(StandardCharsets.US_ASCII)).putLong(i)
                .put((byte) i).array();
            cipher.updateAAD(aad);
            var desde = 18 + i * (c + 16);
            var hasta = i == 0 ? desde + c + 16 : sellado.length;
            var bloque = cipher.doFinal(Arrays.copyOfRange(sellado, desde, hasta));
            assertThat(bloque).isEqualTo(Arrays.copyOfRange(claro, i * c, Math.min(claro.length, (i + 1) * c)));
        }
    }

    @Test
    void unaCabeceraSinNonceCompletoEstaTruncada() {
        var corto = Arrays.copyOf("SAMBK1".getBytes(StandardCharsets.US_ASCII), 11);
        assertThatThrownBy(() -> abrir(corto, KEY)).isInstanceOf(IOException.class).hasMessageContaining("truncado");
    }

    @Test
    void noEsUnRespaldoDeSam() {
        assertThatThrownBy(() -> abrir("PK\u0003\u0004 un zip".getBytes(StandardCharsets.ISO_8859_1), KEY))
            .isInstanceOf(IOException.class).hasMessageContaining("SAMBK1");
        assertThatThrownBy(() -> abrir(new byte[3], KEY)).isInstanceOf(IOException.class).hasMessageContaining("SAMBK1");
    }

    @Test
    void laClaveSaleDeLaVariableEnBase64DeTreintaYDosBytes() {
        var b64 = Base64.getEncoder().encodeToString(KEY);
        assertThat(BackupCrypto.parseKey(" " + b64 + "\n")).isEqualTo(KEY);
        assertThatThrownBy(() -> BackupCrypto.parseKey(null)).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Falta SAM_BACKUP_KEY");
        assertThatThrownBy(() -> BackupCrypto.parseKey("   ")).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Falta SAM_BACKUP_KEY");
        assertThatThrownBy(() -> BackupCrypto.parseKey(Base64.getEncoder().encodeToString(new byte[16])))
            .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("32 bytes");
        assertThatThrownBy(() -> BackupCrypto.parseKey("no es base64 !!")).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("SAM_BACKUP_KEY");
        var nueva = BackupCrypto.newKey(new SecureRandom());
        assertThat(BackupCrypto.parseKey(nueva)).hasSize(32);
        assertThat(BackupCrypto.newKey(new SecureRandom())).isNotEqualTo(nueva);
    }

    @Test
    void unaClaveDeOtroLargoSeRechazaAlSellarYAbrir() {
        assertThatThrownBy(() -> BackupCrypto.seal(new ByteArrayInputStream(new byte[1]), new ByteArrayOutputStream(), new byte[16],
            new SecureRandom())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BackupCrypto.open(new ByteArrayInputStream(new byte[40]), new ByteArrayOutputStream(), new byte[16]))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
