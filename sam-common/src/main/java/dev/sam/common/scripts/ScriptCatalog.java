package dev.sam.common.scripts;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import dev.sam.common.lua.ScriptHost;

/**
 * De los datapacks a los scripts que corren en el servidor (RF-LUA-01, RS-SIG-01/02/04): cada carpeta de
 * {@code sam_scripts/} se verifica contra las claves de confianza; sin firma solo se acepta en modo
 * desarrollo y solo del lado servidor. Los scripts de cliente no corren aquí. El orden respeta las
 * dependencias; si falta una o hay un ciclo, el script se rechaza con su motivo.
 */
public final class ScriptCatalog {

    private static final Pattern FOLDER = Pattern.compile("[a-z0-9_]{1,32}");
    private static final String MANIFEST = "manifest.json";

    public record Rejected(String id, String reason) {
    }

    /** Los scripts de servidor en orden de carga, los rechazados y los avisos para el operador. */
    public record Result(List<ScriptHost.Package> server, List<Rejected> rejected, List<String> warnings) {
    }

    private ScriptCatalog() {
    }

    /** @param folders nombre de la carpeta → (ruta → contenido) de cada script */
    public static Result build(Map<String, Map<String, byte[]>> folders, Collection<SigningPublicKey> trusted, boolean devMode) {
        var rejected = new ArrayList<Rejected>();
        var warnings = new ArrayList<String>();
        var accepted = new TreeMap<String, ScriptHost.Package>();
        for (var entry : new TreeMap<>(folders).entrySet()) {
            var id = entry.getKey();
            try {
                accept(id, entry.getValue(), trusted, devMode, warnings).ifPresent(p -> accepted.put(id, p));
            } catch (IllegalArgumentException e) {
                rejected.add(new Rejected(id, e.getMessage()));
            }
        }
        return new Result(ordered(accepted, rejected), List.copyOf(rejected), List.copyOf(warnings));
    }

    /** @return el paquete si corre en el servidor; vacío si es de cliente; lanza con el motivo si se rechaza */
    private static java.util.Optional<ScriptHost.Package> accept(String id, Map<String, byte[]> files,
            Collection<SigningPublicKey> trusted, boolean devMode, List<String> warnings) {
        if (!FOLDER.matcher(id).matches()) {
            throw new IllegalArgumentException("el nombre de la carpeta debe ser [a-z0-9_], hasta 32");
        }
        var manifestBytes = files.get(MANIFEST);
        if (manifestBytes == null) {
            throw new IllegalArgumentException("falta manifest.json");
        }
        var manifest = ScriptManifest.parse(id, manifestBytes);
        var verdict = ScriptVerifier.verify(files, trusted);
        if (verdict instanceof ScriptVerifier.Result.Invalid invalid) {
            var unsignedServer = invalid.reason() == ScriptVerifier.Reason.MISSING_SIGNATURE && devMode
                && manifest.side() == ScriptManifest.Side.SERVER;
            if (!unsignedServer) {
                throw new IllegalArgumentException(reason(invalid.reason()));
            }
            // Las rutas se validan igual que en un script firmado
            try {
                Lockfile.of(files);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(reason(ScriptVerifier.Reason.INVALID_FILES));
            }
            warnings.add("El script " + id + " no está firmado: solo corre porque el modo desarrollo está activo");
        }
        if (!manifest.runsOnServer()) {
            return java.util.Optional.empty();
        }
        var sources = new LinkedHashMap<String, String>();
        for (var file : new TreeMap<>(files).entrySet()) {
            if (file.getKey().endsWith(".lua")) {
                sources.put(file.getKey(), utf8(file.getKey(), file.getValue()));
            }
        }
        return java.util.Optional.of(new ScriptHost.Package(manifest, sources));
    }

    private static String reason(ScriptVerifier.Reason reason) {
        return switch (reason) {
            case MISSING_SIGNATURE -> "no está firmado";
            case MALFORMED_SIGNATURE -> "signature.json está mal formado";
            case INVALID_FILES -> "tiene archivos con rutas inválidas o demasiados archivos";
            case UNKNOWN_KEY -> "lo firmó una clave que no es de confianza";
            case LOCK_MISMATCH -> "sus archivos no coinciden con la firma (alguno se agregó, quitó o cambió)";
            case BAD_SIGNATURE -> "la firma no es válida";
        };
    }

    private static String utf8(String path, byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException(path + " no es UTF-8 válido");
        }
    }

    /**
     * Orden de carga: un script entra cuando ya entraron todas sus dependencias (por id, para que sea
     * estable). Lo que queda sin poder entrar falta o es circular.
     */
    private static List<ScriptHost.Package> ordered(Map<String, ScriptHost.Package> accepted, List<Rejected> rejected) {
        var pending = new TreeMap<>(accepted);
        // Una dependencia que no está (nunca existió, se rechazó o se descartó) arrastra a quien depende de ella
        var changed = true;
        while (changed) {
            changed = false;
            for (var pack : List.copyOf(pending.values())) {
                var missing = pack.manifest().dependencies().stream()
                    .filter(dep -> !pending.containsKey(dep)).findFirst();
                if (missing.isPresent()) {
                    pending.remove(pack.manifest().id());
                    rejected.add(new Rejected(pack.manifest().id(), "depende de " + missing.get() + ", que no está disponible"));
                    changed = true;
                }
            }
        }
        var order = new ArrayList<ScriptHost.Package>();
        Set<String> loaded = new HashSet<>();
        while (true) {
            var next = pending.values().stream().filter(p -> loaded.containsAll(p.manifest().dependencies())).findFirst();
            if (next.isEmpty()) {
                // Lo que queda (si queda algo) se espera entre sí
                pending.keySet().forEach(id -> rejected.add(new Rejected(id, "dependencia circular")));
                break;
            }
            order.add(next.get());
            loaded.add(next.get().manifest().id());
            pending.remove(next.get().manifest().id());
        }
        return List.copyOf(order);
    }
}
