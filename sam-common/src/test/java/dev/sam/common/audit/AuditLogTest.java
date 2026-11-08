package dev.sam.common.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sam.common.config.FilePermissions;

/** RF-AUTH-08 / RF-AUTH-08a (H-08): auditoría encadenada por hash. */
class AuditLogTest {

    private static final String CEROS = "0".repeat(64);

    @TempDir
    Path dir;

    private Instant ahora = Instant.parse("2026-11-08T12:00:00Z");

    private Path archivo() {
        return dir.resolve("config").resolve("sam").resolve("audit.jsonl");
    }

    private AuditLog abrir() throws Exception {
        return AuditLog.open(archivo(), () -> ahora);
    }

    private static String sha256(String texto) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(texto.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void laPrimeraLineaTieneElFormatoExactoYSuHash() throws Exception {
        abrir().append("login.ok", "Steve", "1.2.3.4", "con 2FA");
        var lineas = Files.readAllLines(archivo());
        assertThat(lineas).hasSize(1);
        var prefijo = "{\"seq\":1,\"t\":\"2026-11-08T12:00:00Z\",\"type\":\"login.ok\",\"actor\":\"Steve\",\"ip\":\"1.2.3.4\","
            + "\"detail\":\"con 2FA\",\"prev\":\"" + CEROS + "\"";
        assertThat(lineas.get(0)).isEqualTo(prefijo + ",\"hash\":\"" + sha256(prefijo) + "\"}");
        assertThat(FilePermissions.readableByOthers(archivo())).isFalse();
    }

    @Test
    void cadaLineaEncadenaLaAnteriorYSobreviveAReabrir() throws Exception {
        var log = abrir();
        log.append("a", "x", "", "");
        ahora = ahora.plusSeconds(1);
        log.append("b", "y", "", "");
        var reabierto = abrir();
        reabierto.append("c", "z", "", "");
        var lineas = Files.readAllLines(archivo());
        assertThat(lineas).hasSize(3);
        for (var i = 1; i < 3; i++) {
            var anterior = lineas.get(i - 1);
            var hashAnterior = anterior.substring(anterior.length() - 66, anterior.length() - 2);
            assertThat(lineas.get(i)).contains("\"seq\":" + (i + 1) + ",").contains("\"prev\":\"" + hashAnterior + "\"");
        }
        assertThat(reabierto.head()).isEqualTo(new AuditLog.Head(3, lineas.get(2).substring(lineas.get(2).length() - 66,
            lineas.get(2).length() - 2)));
    }

    @Test
    void sinArchivoLaCabezaEsCero() throws Exception {
        assertThat(abrir().head()).isEqualTo(new AuditLog.Head(0, CEROS));
        assertThat(Files.exists(archivo())).isFalse();
    }

    @Test
    void escapaComillasBarrasYSaltosDeLinea() throws Exception {
        abrir().append("x", "a\"b", "", "linea1\nlinea2\\fin\t\u0001");
        var linea = Files.readAllLines(archivo()).get(0);
        assertThat(linea).contains("\"actor\":\"a\\\"b\"").contains("\"detail\":\"linea1\\nlinea2\\\\fin\\t\\u0001\"");
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.ok(1));
    }

    @Test
    void verificarUnaCadenaSana() throws Exception {
        var log = abrir();
        for (var i = 0; i < 5; i++) {
            log.append("evento", "j" + i, "10.0.0." + i, "n" + i);
        }
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.ok(5));
        assertThat(AuditLog.verify(dir.resolve("no-existe.jsonl"))).isEqualTo(AuditLog.Verification.ok(0));
    }

    @Test
    void detectaUnaLineaModificada() throws Exception {
        escribirCinco();
        var lineas = new ArrayList<>(Files.readAllLines(archivo()));
        lineas.set(2, lineas.get(2).replace("\"actor\":\"j2\"", "\"actor\":\"otro\""));
        Files.write(archivo(), lineas);
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.broken(3, "el hash no coincide"));
    }

    @Test
    void detectaUnPrevCambiadoAunqueElHashDeLaLineaSeaValido() throws Exception {
        escribirCinco();
        var lineas = new ArrayList<>(Files.readAllLines(archivo()));
        var linea = lineas.get(1);
        var prevViejo = linea.substring(linea.indexOf("\"prev\":\"") + 8, linea.indexOf("\"prev\":\"") + 72);
        var prefijo = linea.substring(0, linea.lastIndexOf(",\"hash\":\"")).replace(prevViejo, "f".repeat(64));
        lineas.set(1, prefijo + ",\"hash\":\"" + sha256(prefijo) + "\"}");
        Files.write(archivo(), lineas);
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.broken(2, "no sigue a la anterior"));
    }

    @Test
    void elResultadoDiceSiEstaSanaCuantasLineasYDondeSeRompe() throws Exception {
        escribirCinco();
        var sana = AuditLog.verify(archivo());
        assertThat(sana.ok()).isTrue();
        assertThat(sana.lines()).isEqualTo(5);
        Files.writeString(archivo(), "basura\n", java.nio.file.StandardOpenOption.APPEND);
        var rota = AuditLog.verify(archivo());
        assertThat(rota.ok()).isFalse();
        assertThat(rota.brokenAt()).isEqualTo(6);
        assertThat(rota.reason()).isEqualTo("línea mal formada");
    }

    @Test
    void noSigueSobreUnaUltimaLineaAlterada() throws Exception {
        escribirCinco();
        var lineas = new ArrayList<>(Files.readAllLines(archivo()));
        lineas.set(4, lineas.get(4).replace("\"actor\":\"j4\"", "\"actor\":\"jX\""));
        Files.write(archivo(), lineas);
        assertThatThrownBy(this::abrir).isInstanceOf(java.io.IOException.class).hasMessageContaining("auditoría");
    }

    @Test
    void unHashQueNoEsHexEsUnaLineaMalFormada() throws Exception {
        escribirCinco();
        var lineas = new ArrayList<>(Files.readAllLines(archivo()));
        var linea = lineas.get(4);
        lineas.set(4, linea.substring(0, linea.length() - 66) + "z".repeat(64) + "\"}");
        Files.write(archivo(), lineas);
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.broken(5, "línea mal formada"));
    }

    @Test
    void detectaUnaLineaBorrada() throws Exception {
        escribirCinco();
        var lineas = new ArrayList<>(Files.readAllLines(archivo()));
        lineas.remove(1);
        Files.write(archivo(), lineas);
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.broken(2, "no sigue a la anterior"));
    }

    @Test
    void detectaUnaCadenaRehechaDesdeElMedioConOtroSeq() throws Exception {
        escribirCinco();
        var lineas = new ArrayList<>(Files.readAllLines(archivo()));
        // Mismo prev y hash válido, pero el número de secuencia salta
        var prefijo = lineas.get(1).substring(0, lineas.get(1).lastIndexOf(",\"hash\":\"")).replace("\"seq\":2,", "\"seq\":7,");
        lineas.set(1, prefijo + ",\"hash\":\"" + sha256(prefijo) + "\"}");
        Files.write(archivo(), lineas);
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.broken(2, "no sigue a la anterior"));
    }

    @Test
    void detectaBasuraYLineasSinHash() throws Exception {
        escribirCinco();
        var lineas = new ArrayList<>(Files.readAllLines(archivo()));
        lineas.set(4, "esto no es json");
        Files.write(archivo(), lineas);
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.broken(5, "línea mal formada"));
        lineas.set(4, "{\"seq\":5}");
        Files.write(archivo(), lineas);
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.broken(5, "línea mal formada"));
    }

    @Test
    void noSigueEscribiendoSobreUnaCadenaRota() throws Exception {
        escribirCinco();
        Files.writeString(archivo(), "basura\n", java.nio.file.StandardOpenOption.APPEND);
        assertThatThrownBy(this::abrir).isInstanceOf(java.io.IOException.class).hasMessageContaining("auditoría");
    }

    @Test
    void lasUltimasLineas() throws Exception {
        escribirCinco();
        assertThat(AuditLog.last(archivo(), 2)).hasSize(2).allSatisfy(l -> assertThat(l).startsWith("{\"seq\":"));
        assertThat(AuditLog.last(archivo(), 2).get(1)).contains("\"seq\":5,");
        assertThat(AuditLog.last(archivo(), 99)).hasSize(5);
        assertThat(AuditLog.last(archivo(), 0)).isEmpty();
        assertThat(AuditLog.last(dir.resolve("no-existe"), 3)).isEmpty();
    }

    @Test
    void exportarHaceUnaCopiaSoloDelDueno() throws Exception {
        escribirCinco();
        var copia = AuditLog.export(archivo(), ahora);
        assertThat(copia.getFileName().toString()).isEqualTo("audit-export-20261108-120000.jsonl");
        assertThat(copia.getParent()).isEqualTo(archivo().getParent());
        assertThat(Files.readAllLines(copia)).isEqualTo(Files.readAllLines(archivo()));
        assertThat(FilePermissions.readableByOthers(copia)).isFalse();
    }

    @Test
    void esSeguroEntreHilos() throws Exception {
        var log = abrir();
        var hilos = new ArrayList<Thread>();
        for (var h = 0; h < 4; h++) {
            var n = h;
            hilos.add(Thread.ofPlatform().start(() -> {
                for (var i = 0; i < 50; i++) {
                    try {
                        log.append("t", "h" + n, "", "" + i);
                    } catch (java.io.IOException e) {
                        throw new java.io.UncheckedIOException(e);
                    }
                }
            }));
        }
        for (var hilo : hilos) {
            hilo.join();
        }
        assertThat(AuditLog.verify(archivo())).isEqualTo(AuditLog.Verification.ok(200));
    }

    private void escribirCinco() throws Exception {
        var log = abrir();
        for (var i = 0; i < 5; i++) {
            log.append("evento", "j" + i, "", "");
        }
    }

    @Test
    void losEventosDeUnActorSinImportarMayusculas() throws Exception {
        var log = abrir();
        log.append("login.ok", "Steve", "1.1.1.1", "");
        log.append("login.ok", "Alex", "2.2.2.2", "");
        log.append("comando", "steve", "", "gamemode creative");
        log.append("permisos.cambio", "Steve2", "", "");
        var lineas = AuditLog.byActor(archivo(), "STEVE");
        assertThat(lineas).hasSize(2);
        assertThat(lineas.get(0)).contains("\"seq\":1,");
        assertThat(lineas.get(1)).contains("gamemode creative");
        assertThat(AuditLog.byActor(dir.resolve("no-existe"), "steve")).isEmpty();
        Files.writeString(archivo(), "basura\n", java.nio.file.StandardOpenOption.APPEND);
        assertThat(AuditLog.byActor(archivo(), "steve")).hasSize(2);
    }
}
