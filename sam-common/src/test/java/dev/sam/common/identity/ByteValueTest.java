package dev.sam.common.identity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ByteValueTest {

    @Test
    void valoresDeTiposDistintosNuncaSonIguales() {
        // Mismo contenido de bytes no implica mismo valor si el tipo difiere
        var id = ServerId.of(new byte[16]);
        var pin = Pin.of(new byte[32]);
        assertThat((Object) id).isNotEqualTo(pin);
        assertThat((Object) pin).isNotEqualTo(id);
    }

    @Test
    void toStringIndicaElTipo() {
        assertThat(ServerId.of(new byte[16]).toString()).startsWith("ServerId[");
        assertThat(Pin.of(new byte[32]).toString()).startsWith("Pin[");
    }

    @Test
    void elMensajeDeErrorIndicaQueValorFallo() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> Pin.of(new byte[1]))
            .hasMessageContaining("pin").hasMessageContaining("32");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> ServerId.fromHex("zz"))
            .hasMessageContaining("server_id").hasMessageContaining("32 dígitos");
    }

    @Test
    void unHexDeLongitudCorrectaConCaracteresInvalidosDaElMismoMensaje() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> ServerId.fromHex("0000000000000000000000000000000g"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("server_id").hasMessageContaining("32 dígitos");
    }
}
