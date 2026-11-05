package dev.sam.common.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * El archivo {@code .env} en disco (RF-CFG-01/03/09): dónde está, su creación con valores por defecto
 * seguros en el primer arranque y su protección (RN-34).
 */
public final class EnvFile {

    public static final String ENV_FILE = "SAM_ENV_FILE";
    public static final String DEFAULT_LOCATION = "config/sam/.env";
    public static final String EXAMPLE_NAME = ".env.example";
    public static final String GITIGNORE_NAME = ".gitignore";

    private static final String WS_PATH_PLACEHOLDER = "{{SAM_WS_PATH}}";
    private static final String TEMPLATE = """
        # SAM: configuración del servidor. Este archivo vive solo en el servidor y nunca se envía al cliente.
        # Las variables de entorno reales del proceso tienen prioridad sobre este archivo.
        # Para usar otro archivo, define SAM_ENV_FILE en el entorno del proceso.
        # [reinicio] = el cambio aplica al reiniciar el servidor.
        #
        # Secretos maestros: SOLO como variables de entorno del proceso. Si aparecen aquí, SAM no arranca.
        #   SAM_DATA_KEY             cifra TOTP y correos en reposo
        #   SAM_IDENTITY_PASSPHRASE  descifra la clave del certificado del servidor

        # ===== Red y transporte =====
        # [reinicio] Conexiones TCP directas (false = solo WebSocket, recomendado detrás de un CDN)
        SAM_TCP_ENABLED=true
        # [reinicio] WebSocket en el mismo puerto, para pasar por Cloudflare
        SAM_WS_ENABLED=false
        # [reinicio] Ruta del WebSocket (otra ruta responde 404). SAM la genera al crear el .env.
        SAM_WS_PATH={{SAM_WS_PATH}}
        # [reinicio] Proxies de los que se acepta la IP real: cloudflare | lista de CIDR separada por comas | vacío
        SAM_WS_TRUSTED_PROXIES=cloudflare
        # [reinicio] Cabecera con la IP real: CF-Connecting-IP | X-Forwarded-For
        SAM_WS_REAL_IP_HEADER=CF-Connecting-IP
        # [reinicio] Conexiones sin clasificar (incluye el handshake WebSocket): por IP y en total
        SAM_NET_UNCLASSIFIED_PER_IP=8
        SAM_NET_UNCLASSIFIED_GLOBAL=256
        """;

    /**
     * @param created {@code true} si se generó en este arranque
     * @param warnings avisos para la consola (por ejemplo, permisos abiertos)
     */
    public record Loaded(Path file, Map<String, String> values, boolean created, List<String> warnings) {
    }

    private EnvFile() {
    }

    /** {@value #DEFAULT_LOCATION} o {@value #ENV_FILE} del entorno, relativa a la carpeta del servidor. */
    public static Path locate(Path serverDir, Map<String, String> process) {
        var configured = process.getOrDefault(ENV_FILE, "").strip();
        return serverDir.resolve(configured.isEmpty() ? DEFAULT_LOCATION : configured);
    }

    /**
     * Lee el {@code .env}; si no existe, lo genera. Mantiene al lado el {@value #EXAMPLE_NAME} y un
     * {@value #GITIGNORE_NAME} que lo excluye.
     *
     * @param forbidden carpetas donde el {@code .env} no puede estar (la del mundo); tampoco dentro de
     *        una carpeta {@code datapacks}
     * @throws IllegalArgumentException si está en un lugar prohibido o su contenido es inválido
     */
    public static Loaded load(Path file, List<Path> forbidden, SecureRandom random) throws IOException {
        checkLocation(file, forbidden);
        var dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        var warnings = new ArrayList<String>();
        var created = !Files.exists(file);
        if (created) {
            Files.writeString(file, template(randomWsPath(random)));
            FilePermissions.restrictToOwner(file);
        } else if (FilePermissions.readableByOthers(file)) {
            warnings.add("El .env (" + file + ") lo pueden leer otros usuarios del sistema: restringe sus permisos para que "
                + "solo lo lea el usuario del servidor (RF-CFG-09).");
        }
        Files.writeString(dir.resolve(EXAMPLE_NAME), template(""));
        ignore(dir.resolve(GITIGNORE_NAME), file.getFileName().toString());
        try {
            return new Loaded(file, DotEnv.parse(Files.readString(file)), created, List.copyOf(warnings));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage() + " (" + file + ")", e);
        }
    }

    /** El contenido por defecto; {@code wsPath} vacío en el ejemplo. */
    static String template(String wsPath) {
        return TEMPLATE.replace(WS_PATH_PLACEHOLDER, wsPath);
    }

    /** Ruta difícil de adivinar (RF-WS-02): 128 bits aleatorios en base64url. */
    private static String randomWsPath(SecureRandom random) {
        var bytes = new byte[16];
        random.nextBytes(bytes);
        return "/sam-" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Con la ruta real (enlaces resueltos), para que un enlace no esconda el mundo. */
    private static void checkLocation(Path file, List<Path> forbidden) throws IOException {
        var path = file.toAbsolutePath().normalize();
        var real = real(path);
        for (var element : real) {
            if (element.toString().toLowerCase(Locale.ROOT).equals("datapacks")) {
                throw new IllegalArgumentException("El .env (" + path + ") está dentro de una carpeta de datapacks: se "
                    + "distribuiría con el datapack. Muévelo a config/sam/ (RF-CFG-09).");
            }
        }
        for (var dir : forbidden) {
            var world = dir.toAbsolutePath().normalize();
            if (real.startsWith(real(world))) {
                throw new IllegalArgumentException("El .env (" + path + ") está dentro de la carpeta del mundo (" + world
                    + "): podría copiarse en un backup o compartirse con el mundo. Muévelo a config/sam/ (RF-CFG-09).");
            }
        }
    }

    /** La ruta con los enlaces resueltos hasta donde existe; la raíz siempre existe. */
    private static Path real(Path path) throws IOException {
        var existing = path;
        while (!Files.exists(existing)) {
            existing = existing.getParent();
        }
        return existing.toRealPath().resolve(existing.relativize(path));
    }

    /** Agrega el nombre al .gitignore si falta, sin tocar lo demás. */
    private static void ignore(Path gitignore, String name) throws IOException {
        var text = Files.exists(gitignore) ? Files.readString(gitignore) : "";
        if (text.lines().noneMatch(line -> line.strip().equals(name))) {
            var separator = text.isEmpty() || text.endsWith("\n") ? "" : "\n";
            Files.writeString(gitignore, text + separator + name + "\n");
        }
    }
}
