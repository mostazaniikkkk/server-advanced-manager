package dev.sam.signer;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.regex.Pattern;

import dev.sam.common.config.FilePermissions;
import dev.sam.common.scripts.Lockfile;
import dev.sam.common.scripts.ScriptCatalog;
import dev.sam.common.scripts.ScriptManifest;
import dev.sam.common.scripts.ScriptSigner;
import dev.sam.common.scripts.ScriptVerifier;
import dev.sam.common.scripts.SigningPublicKey;
import dev.sam.common.scripts.TrustStore;

/**
 * sam-signer (RS-SIG-01/07): la herramienta del operador para firmar scripts en su PC. La clave privada
 * nunca va al servidor: allí solo se copia el {@code .pub} a {@code config/sam/keys/trusted/} y se
 * confirma desde la consola.
 */
public final class SamSigner {

    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9_-]{1,32}");
    private static final String USAGE = """
        Uso:
          sam-signer keygen <nombre>                      crea <nombre>.key (cifrada) y <nombre>.pub
          sam-signer sign <carpeta> --key <archivo.key>   firma la carpeta de un script (escribe signature.json)
          sam-signer verify <carpeta> --pub <archivo.pub> verifica la firma con una clave pública
        La passphrase se pide por consola (o en SAM_SIGNER_PASSPHRASE si no hay consola).""";

    /** Lo que la herramienta necesita del mundo exterior (inyectable en las pruebas). */
    record Env(Path cwd, PrintStream out, Function<String, char[]> passphrase, SecureRandom random, int iterations) {
    }

    private SamSigner() {
    }

    public static void main(String[] args) {
        var console = System.console();
        var env = new Env(Path.of("").toAbsolutePath(), System.out,
            prompt -> prompt(console == null ? null : text -> console.readPassword("%s", text), System.getenv(), prompt), new SecureRandom(),
            SigningKeyFile.ITERATIONS);
        System.exit(run(args, env));
    }

    /**
     * La passphrase de la consola; si no hay, o no se puede leer (Java 22+ da una consola aunque la salida
     * esté redirigida), de SAM_SIGNER_PASSPHRASE.
     */
    static char[] prompt(Function<String, char[]> console, Map<String, String> environment, String prompt) {
        if (console != null) {
            try {
                return console.apply(prompt);
            } catch (java.io.IOError e) {
                // Sin terminal real: sigue con el entorno
            }
        }
        return fromEnvironment(environment);
    }

    /** Sin consola (por ejemplo en CI), la passphrase puede venir de SAM_SIGNER_PASSPHRASE. */
    static char[] fromEnvironment(Map<String, String> environment) {
        var value = environment.get("SAM_SIGNER_PASSPHRASE");
        return value == null ? null : value.toCharArray();
    }

    /** @return 0 si salió bien, 1 si falló, 2 si los argumentos no son válidos */
    static int run(String[] args, Env env) {
        try {
            if (args.length == 2 && args[0].equals("keygen")) {
                keygen(args[1], env);
                return 0;
            }
            if (args.length == 4 && args[0].equals("sign") && args[2].equals("--key")) {
                sign(env.cwd().resolve(args[1]), env.cwd().resolve(args[3]), env);
                return 0;
            }
            if (args.length >= 4 && args.length % 2 == 0 && args[0].equals("verify")) {
                return verify(args, env);
            }
        } catch (IllegalArgumentException | IOException e) {
            env.out().println("Error: " + e.getMessage());
            return 1;
        }
        env.out().println(USAGE);
        return 2;
    }

    private static void keygen(String name, Env env) throws IOException {
        if (!NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("el nombre debe ser [A-Za-z0-9_-], hasta 32");
        }
        var keyFile = env.cwd().resolve(name + ".key");
        var pubFile = env.cwd().resolve(name + ".pub");
        if (Files.exists(keyFile) || Files.exists(pubFile)) {
            throw new IllegalArgumentException(keyFile.getFileName() + " o " + pubFile.getFileName() + " ya existe: no se pisa una clave");
        }
        var first = passphrase(env, "Passphrase nueva (al menos " + SigningKeyFile.MIN_PASSPHRASE + " caracteres): ");
        var second = passphrase(env, "Repítela: ");
        try {
            if (!Arrays.equals(first, second)) {
                throw new IllegalArgumentException("las passphrases no coinciden");
            }
            var key = SigningKeyFile.generate(env.random());
            var pem = SigningKeyFile.encrypt(key, first, env.random(), env.iterations());
            Files.writeString(keyFile, pem);
            FilePermissions.restrictToOwner(keyFile);
            Files.writeString(pubFile, SigningKeyFile.publicFile(key, name));
            env.out().println("Clave creada: " + keyFile.getFileName() + " (privada, cifrada; guárdala en un gestor de contraseñas) y "
                + pubFile.getFileName() + " (pública, key_id " + SigningPublicKey.of(key.publicKeyRaw()).keyId().hex() + ").");
            env.out().println("En el servidor: copia " + pubFile.getFileName() + " a config/sam/keys/trusted/ y confírmala desde la consola.");
        } finally {
            Secrets.wipe(first, second);
        }
    }

    private static void sign(Path folder, Path keyFile, Env env) throws IOException {
        var files = readFolder(folder);
        var manifest = files.get("manifest.json");
        if (manifest == null) {
            throw new IllegalArgumentException("falta manifest.json en " + folder);
        }
        var parsed = ScriptManifest.parse(folder.getFileName().toString(), manifest);
        var passphrase = passphrase(env, "Passphrase de " + keyFile.getFileName() + ": ");
        SigningKeyFile.SigningKey key;
        try {
            key = SigningKeyFile.decrypt(Files.readString(keyFile), passphrase);
        } finally {
            Secrets.wipe(passphrase);
        }
        Files.write(folder.resolve(Lockfile.SIGNATURE_FILE), ScriptSigner.sign(files, key.privateKey()));
        env.out().println("Firmado " + parsed.id() + " con la clave " + SigningPublicKey.of(key.publicKeyRaw()).keyId().hex() + ".");
    }

    private static int verify(String[] args, Env env) throws IOException {
        var keys = new ArrayList<SigningPublicKey>();
        for (var i = 2; i < args.length; i += 2) {
            if (!args[i].equals("--pub")) {
                throw new IllegalArgumentException("se esperaba --pub");
            }
            keys.add(TrustStore.parsePublic(Files.readString(env.cwd().resolve(args[i + 1])))
                .orElseThrow(() -> new IllegalArgumentException("no es una clave pública Ed25519 en base64")));
        }
        var result = ScriptVerifier.verify(readFolder(env.cwd().resolve(args[1])), keys);
        if (result instanceof ScriptVerifier.Result.Valid valid) {
            env.out().println("Firma válida (key_id " + valid.keyId().hex() + ").");
            return 0;
        }
        env.out().println("Firma inválida: " + ScriptCatalog.describe(((ScriptVerifier.Result.Invalid) result).reason()));
        return 1;
    }

    private static char[] passphrase(Env env, String prompt) {
        var value = env.passphrase().apply(prompt);
        if (value == null) {
            throw new IllegalArgumentException("no se pudo leer la passphrase (usa una consola o SAM_SIGNER_PASSPHRASE)");
        }
        return value;
    }

    /** Los archivos de la carpeta de un script, con rutas relativas separadas por {@code /}. */
    static Map<String, byte[]> readFolder(Path folder) throws IOException {
        var files = new TreeMap<String, byte[]>();
        try (var walk = Files.walk(folder)) {
            for (var file : walk.filter(Files::isRegularFile).toList()) {
                files.put(folder.relativize(file).toString().replace('\\', '/'), Files.readAllBytes(file));
            }
        }
        return files;
    }
}
