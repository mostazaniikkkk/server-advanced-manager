package dev.sam.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

import org.junit.jupiter.api.Test;

/** El formato del .env (RF-CFG-01): lo que no se entiende se rechaza con su línea (RF-CFG-04). */
class DotEnvTest {

    @Test
    void leeClavesEnOrdenIgnorandoComentariosYLineasVacias() {
        var valores = DotEnv.parse("""
            # ===== Red =====

            SAM_TCP_ENABLED=true
              SAM_WS_ENABLED = false
            SAM_LANG=es_es
            """);
        assertThat(valores).containsExactly(entry("SAM_TCP_ENABLED", "true"), entry("SAM_WS_ENABLED", "false"),
            entry("SAM_LANG", "es_es"));
    }

    @Test
    void elComentarioEnLineaEmpiezaEnUnNumeralPrecedidoDeEspacio() {
        var valores = DotEnv.parse("""
            SAM_WS_PATH=/a#b          # ruta
            SAM_A=	#solo comentario
            SAM_B=#literal
            SAM_C=
            """);
        assertThat(valores).containsExactly(entry("SAM_WS_PATH", "/a#b"), entry("SAM_A", ""), entry("SAM_B", "#literal"),
            entry("SAM_C", ""));
    }

    @Test
    void lasComillasDoblesAdmitenEspaciosNumeralesYEscapes() {
        var valores = DotEnv.parse("SAM_MAIL_FROM=\"Mi Servidor <no-reply@example.com>\"  # remitente\n"
            + "SAM_X=\"a \\\"b\\\" c\\\\d\\ne # no es comentario\"\n");
        assertThat(valores).containsExactly(entry("SAM_MAIL_FROM", "Mi Servidor <no-reply@example.com>"),
            entry("SAM_X", "a \"b\" c\\d\ne # no es comentario"));
    }

    @Test
    void lasComillasSimplesSonLiterales() {
        assertThat(DotEnv.parse("SAM_X='a \\n \"b\" # c'\n")).containsExactly(entry("SAM_X", "a \\n \"b\" # c"));
    }

    @Test
    void aceptaFinesDeLineaWindowsYMarcaDeOrdenDeBytes() {
        assertThat(DotEnv.parse("﻿SAM_A=1\r\nSAM_B=\"x\"\r\n")).containsExactly(entry("SAM_A", "1"), entry("SAM_B", "x"));
    }

    @Test
    void unaLineaSinIgualSeRechazaConSuNumero() {
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=1\n\nSAM_TCP_ENABLED true\n"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage(".env, línea 3: se esperaba CLAVE=valor");
    }

    @Test
    void unaClaveInvalidaSeRechaza() {
        for (var linea : new String[] {"sam_a=1", "=1", "1SAM=1", "SAM-A=1", "export SAM_A=1", "SAM A=1"}) {
            assertThatThrownBy(() -> DotEnv.parse(linea)).as(linea)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith(".env, línea 1: clave inválida \"");
        }
        assertThat(DotEnv.parse("A=1\nZ9_=2\n")).containsExactly(entry("A", "1"), entry("Z9_", "2"));
    }

    @Test
    void unaClaveRepetidaSeRechazaNombrandoAmbasLineas() {
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=1\n# x\nSAM_A=2\n"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage(".env, línea 3: SAM_A repetida (ya definida en la línea 1)");
    }

    @Test
    void lasComillasSinCerrarOConTextoDetrasSeRechazan() {
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=\"abc\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: comillas sin cerrar");
        assertThatThrownBy(() -> DotEnv.parse("SAM_A='abc\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: comillas sin cerrar");
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=\"abc\\\"\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: comillas sin cerrar");
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=\"abc\"def\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: texto después de las comillas");
        // Barra final: no escapa nada, las comillas siguen abiertas
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=\"abc\\\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: comillas sin cerrar");
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=\"abc\" def\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: texto después de las comillas");
        assertThatThrownBy(() -> DotEnv.parse("SAM_A='abc'#x\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: texto después de las comillas");
        assertThat(DotEnv.parse("SAM_A=\"abc\"\t\nSAM_B='x' # c\n")).containsExactly(entry("SAM_A", "abc"), entry("SAM_B", "x"));
    }

    @Test
    void unEscapeDesconocidoSeRechaza() {
        assertThatThrownBy(() -> DotEnv.parse("SAM_A=\"a\\tb\"\n"))
            .isInstanceOf(IllegalArgumentException.class).hasMessage(".env, línea 1: escape inválido \\t");
    }

    @Test
    void unArchivoVacioNoTieneClaves() {
        assertThat(DotEnv.parse("")).isEmpty();
        assertThat(DotEnv.parse("\n# nada\n   \n")).isEmpty();
    }
}
