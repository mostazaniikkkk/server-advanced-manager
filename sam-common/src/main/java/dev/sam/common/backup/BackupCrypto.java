package dev.sam.common.backup;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * RF-CFG-11 (H-16 de HARDENING.md): cifrado de respaldos por bloques (construcción STREAM). Cabecera
 * {@code SAMBK1} y un nonce base de 12 bytes; después, bloques de hasta {@link #CHUNK} bytes, cada uno con
 * AES-256-GCM, nonce = base XOR número de bloque, y AAD = cabecera + número de bloque + si es el último. Así un
 * bloque cambiado, quitado, reordenado o un archivo truncado no abren. Nunca guarda el respaldo entero en memoria.
 */
public final class BackupCrypto {

    public static final int CHUNK = 1 << 20;
    public static final String ENV = "SAM_BACKUP_KEY";
    private static final byte[] MAGIC = "SAMBK1".getBytes(StandardCharsets.US_ASCII);
    private static final int NONCE = 12;
    private static final int TAG = 16;
    private static final int KEY = 32;

    private BackupCrypto() {
    }

    public static void seal(InputStream in, OutputStream out, byte[] key, SecureRandom random) throws IOException {
        var spec = key(key);
        var base = new byte[NONCE];
        random.nextBytes(base);
        out.write(MAGIC);
        out.write(base);
        var current = in.readNBytes(CHUNK);
        for (long index = 0;; index++) {
            var next = in.readNBytes(CHUNK);
            var last = next.length == 0;
            out.write(crypt(Cipher.ENCRYPT_MODE, spec, base, index, last, current));
            if (last) {
                return;
            }
            current = next;
        }
    }

    public static void open(InputStream in, OutputStream out, byte[] key) throws IOException {
        var spec = key(key);
        if (!Arrays.equals(in.readNBytes(MAGIC.length), MAGIC)) {
            throw new IOException("no es un respaldo cifrado de SAM (falta la cabecera SAMBK1)");
        }
        var base = in.readNBytes(NONCE);
        if (base.length < NONCE) {
            throw new IOException("el respaldo está truncado");
        }
        // Se lee un byte de más para saber si el bloque es el último; ese byte abre el bloque siguiente
        var carry = new byte[0];
        for (long index = 0;; index++) {
            var rest = in.readNBytes(CHUNK + TAG - carry.length);
            var block = ByteBuffer.allocate(carry.length + rest.length).put(carry).put(rest).array();
            carry = in.readNBytes(1);
            var last = carry.length == 0;
            // Un bloque de menos de 16 bytes no tiene etiqueta: GCM lo rechaza como dañado
            out.write(crypt(Cipher.DECRYPT_MODE, spec, base, index, last, block));
            if (last) {
                return;
            }
        }
    }

    /** La clave de {@code SAM_BACKUP_KEY}: 32 bytes en base64. */
    public static byte[] parseKey(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Falta " + ENV + " en el entorno (genera una con: sam-signer backup-key)");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(value.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(ENV + " no es base64 válido");
        }
        if (key.length != KEY) {
            throw new IllegalArgumentException(ENV + " debe tener 32 bytes (tiene " + key.length + ")");
        }
        return key;
    }

    /** Una clave nueva para {@code SAM_BACKUP_KEY}. */
    public static String newKey(SecureRandom random) {
        var key = new byte[KEY];
        random.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private static SecretKeySpec key(byte[] key) {
        if (key.length != KEY) {
            throw new IllegalArgumentException("la clave de respaldo debe tener 32 bytes");
        }
        return new SecretKeySpec(key, "AES");
    }

    private static byte[] crypt(int mode, SecretKeySpec key, byte[] base, long index, boolean last, byte[] data)
            throws IOException {
        var nonce = base.clone();
        var counter = ByteBuffer.allocate(8).putLong(index).array();
        for (var i = 0; i < 8; i++) {
            nonce[NONCE - 8 + i] ^= counter[i];
        }
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, key, new GCMParameterSpec(TAG * 8, nonce));
            cipher.updateAAD(ByteBuffer.allocate(MAGIC.length + 9).put(MAGIC).putLong(index).put((byte) (last ? 1 : 0)).array());
            return cipher.doFinal(data);
        } catch (AEADBadTagException e) {
            throw new IOException("el respaldo está dañado o la clave no es la correcta");
        } catch (GeneralSecurityException e) {
            throw new IOException("no se pudo cifrar o descifrar el respaldo: " + e.getMessage(), e);
        }
    }
}
