package dev.sam.signer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

import dev.sam.common.backup.BackupCrypto;
import dev.sam.common.config.SecureFiles;

/**
 * RF-CFG-11: respaldos cifrados en disco. Escribe en un temporal solo del dueño y lo mueve al final, nunca
 * pisa un archivo y deja el {@code .sha256} al lado del cifrado; al abrir, lo exige y lo compara antes de descifrar.
 */
final class BackupFiles {

    private BackupFiles() {
    }

    static void seal(Path in, Path out, byte[] key, SecureRandom random) throws IOException {
        refuseExisting(out);
        var hash = toFile(out, sink -> {
            try (var source = Files.newInputStream(in)) {
                BackupCrypto.seal(source, sink, key, random);
            }
        });
        SecureFiles.writeString(sidecar(out), hash + "  " + out.getFileName() + "\n");
    }

    static void open(Path in, Path out, byte[] key) throws IOException {
        refuseExisting(out);
        var sidecar = sidecar(in);
        if (!Files.exists(sidecar)) {
            throw new IOException("falta " + sidecar.getFileName() + ": sin el hash no se puede comprobar el respaldo");
        }
        var expected = Files.readString(sidecar, StandardCharsets.UTF_8).strip().split("\\s+")[0];
        if (!expected.equals(sha256(in))) {
            throw new IOException("el hash de " + in.getFileName() + " no coincide con " + sidecar.getFileName());
        }
        toFile(out, sink -> {
            try (var source = Files.newInputStream(in)) {
                BackupCrypto.open(source, sink, key);
            }
        });
    }

    private interface Writer {
        void write(OutputStream out) throws IOException;
    }

    /** Escribe con {@link SecureFiles} (temporal solo del dueño, sin pisar nada); devuelve el SHA-256 de lo escrito. */
    private static String toFile(Path out, Writer writer) throws IOException {
        var digest = digest();
        SecureFiles.write(out, file -> writer.write(new java.security.DigestOutputStream(file, digest)), false);
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String sha256(Path file) throws IOException {
        var digest = digest();
        try (InputStream in = new DigestInputStream(Files.newInputStream(file), digest)) {
            in.transferTo(OutputStream.nullOutputStream());
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static MessageDigest digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void refuseExisting(Path out) {
        if (Files.exists(out)) {
            throw new IllegalArgumentException(out.getFileName() + " ya existe: no se pisa");
        }
    }

    private static Path sidecar(Path file) {
        return file.resolveSibling(file.getFileName() + ".sha256");
    }
}
