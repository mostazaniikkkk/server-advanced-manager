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
