package dev.sam.server;

import java.io.IOException;
import java.nio.file.Path;
import java.time.InstantSource;

import org.slf4j.Logger;

import dev.sam.common.audit.AuditLog;

/**
 * La auditoría del servidor (RF-AUTH-08, H-08 y H-09 de HARDENING.md): cada evento va a la cadena por hash de
 * {@code config/sam/audit.jsonl} y también al log del servidor con {@code [auditoría]}. Si la cadena no se puede
 * abrir (por ejemplo, termina en una línea rota), los eventos siguen yendo al log y se avisa en cada uno.
 */
public final class SamAudit {

    private static volatile Logger logger;
    private static volatile AuditLog chain;
    private static volatile Path file;
    private static volatile dev.sam.common.audit.SensitiveCommands sensitive =
        dev.sam.common.audit.SensitiveCommands.fromConfig(java.util.Map.of());

    /** Qué comandos vanilla se auditan ({@code SAM_AUDIT_COMMANDS}). */
    static void commands(dev.sam.common.audit.SensitiveCommands commands) {
        sensitive = commands;
    }

    /** RF-ADM-06a: un comando que acaba de mandar {@code actor}; solo los sensibles quedan registrados. */
    public static void command(String actor, String command) {
        if (sensitive.matches(command)) {
            event("comando", actor, "", command.strip());
        }
    }

    private SamAudit() {
    }

    static void install(Logger log, Path path) {
        logger = log;
        file = path;
        try {
            chain = AuditLog.open(path, InstantSource.system());
            var head = chain.head();
            // El ancla externa: con ella se detecta una cadena truncada al final (RF-AUTH-08a)
            log.info("Auditoría encadenada en {}: {} eventos, cabeza {}", path, head.seq(), head.hash());
        } catch (IOException e) {
            chain = null;
            log.error("La auditoría encadenada no está disponible ({}). Los eventos van solo a este log.", e.getMessage());
        }
    }

    private static volatile java.time.Duration retention = java.time.Duration.ofDays(90);
    private static volatile java.time.Instant lastAnonymize = java.time.Instant.EPOCH;

    /** {@code SAM_AUDIT_IP_RETENTION} (RF-AUTH-08b). */
    static void retention(java.time.Duration value) {
        retention = value;
    }

    /** RF-AUTH-08b (H-11): una vez por día (y al arrancar), borra las IPs más viejas que la retención. */
    static void anonymizeIfDue(java.time.Instant now) {
        var current = chain;
        if (current == null || now.isBefore(lastAnonymize.plus(java.time.Duration.ofDays(1)))) {
            return;
        }
        lastAnonymize = now;
        try {
            current.anonymizeBefore(now.minus(retention)).ifPresent(done -> event("auditoria.anonimizada", "SAM", "",
                done.lines() + " IPs de más de " + (retention.toDays() > 0 ? retention.toDays() + " días" : retention.toSeconds() + " s")
                    + " borradas; cabeza anterior " + done.before().seq() + " "
                    + done.before().hash() + ", nueva " + done.after().hash()));
        } catch (IOException | RuntimeException e) {
            var log = logger;
            if (log != null) {
                log.error("No se pudieron anonimizar las IPs viejas de la auditoría: {}", e.getMessage());
            }
        }
    }

    /** El archivo de la cadena (para {@code /sam audit}). */
    public static Path file() {
        return file;
    }

    /**
     * @param type qué pasó, en minúsculas con puntos (por ejemplo {@code login.fallido})
     * @param actor quién (nick, "consola"...)
     * @param ip la IP real, o vacío si no aplica
     * @param detail el motivo o los datos del evento
     */
    public static void event(String type, String actor, String ip, String detail) {
        var log = logger;
        if (log != null) {
            log.info("[auditoría] {} {}{}: {}", type, actor, ip.isEmpty() ? "" : " desde " + ip, detail);
        }
        var current = chain;
        if (current == null) {
            return;
        }
        try {
            current.append(type, actor, ip, detail);
        } catch (IOException e) {
            if (log != null) {
                log.error("No se pudo escribir en la auditoría encadenada: {}", e.getMessage());
            }
        }
    }
}
