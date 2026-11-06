package dev.sam.server.auth;

import io.netty.handler.codec.DecoderException;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

/**
 * Un mensaje SAM como custom payload {@code sam:<nombre>} (PROTOCOLO.md 4.1). El payload lleva los
 * bytes del mensaje; se decodifican con el codec estricto de sam-common. El tamaño se limita antes de
 * copiar nada (5.6).
 */
public record SamPayload(CustomPacketPayload.Type<SamPayload> type, byte[] data) implements CustomPacketPayload {

    public static CustomPacketPayload.Type<SamPayload> type(String name) {
        return new CustomPacketPayload.Type<>(ResourceLocation.fromNamespaceAndPath("sam", name));
    }

    public static StreamCodec<FriendlyByteBuf, SamPayload> codec(CustomPacketPayload.Type<SamPayload> type, int maxBytes) {
        return StreamCodec.of((buf, payload) -> buf.writeBytes(payload.data()), buf -> {
            var length = buf.readableBytes();
            if (length > maxBytes) {
                throw new DecoderException(type.id() + ": " + length + " bytes, máximo " + maxBytes + " [SAM-P001]");
            }
            var data = new byte[length];
            buf.readBytes(data);
            return new SamPayload(type, data);
        });
    }
}
