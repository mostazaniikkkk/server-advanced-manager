package dev.sam.common.proto.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import dev.sam.common.proto.ProtocolException;
import dev.sam.common.proto.SamReader;
import dev.sam.common.proto.SamWriter;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

/** PROTOCOLO.md 5.7 (RF-AUTH-07e): exportar y borrar los datos del jugador. */
class AccountDataTest {

    private static byte[] bytes(java.util.function.Consumer<SamWriter> w) {
        var buf = Unpooled.buffer();
        w.accept(new SamWriter(buf));
        return ByteBufUtil.getBytes(buf);
    }

    @Test
    void idaYVuelta() {
        var k = new byte[32];
        k[0] = 7;
        for (var accion : AccountData.Action.values()) {
            for (var codigo : java.util.List.of(Optional.<String>empty(), Optional.of("123456"))) {
                var m = new AccountData(accion, k, codigo);
                var leido = SamReader.decode(Unpooled.wrappedBuffer(bytes(m::write)), AccountData.MAX_BYTES, AccountData::read);
                assertThat(leido.action()).isEqualTo(accion);
                assertThat(leido.k()).isEqualTo(k);
                assertThat(leido.code()).isEqualTo(codigo);
            }
        }
        assertThat(AccountData.ID).isEqualTo("account_data");
    }

    @Test
    void kDebeTener32Bytes() {
        assertThatThrownBy(() -> new AccountData(AccountData.Action.DELETE, new byte[3], Optional.empty()))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    void laExportacionVaYVuelveConSuTope() {
        var json = "{\"nick\":\"Steve\",\"ñ\":true}";
        var leido = SamReader.decode(Unpooled.wrappedBuffer(bytes(new AccountExport(json)::write)), AccountExport.MAX_BYTES,
            AccountExport::read);
        assertThat(leido.json()).isEqualTo(json);
        assertThat(AccountExport.ID).isEqualTo("account_export");
        assertThat(AccountExport.MAX_JSON).isEqualTo(65536);
        var largo = "x".repeat(AccountExport.MAX_JSON + 1);
        assertThatThrownBy(() -> bytes(new AccountExport(largo)::write)).isInstanceOf(RuntimeException.class);
    }
}
