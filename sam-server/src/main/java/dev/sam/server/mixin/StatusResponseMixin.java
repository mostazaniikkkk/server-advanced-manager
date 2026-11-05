package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

import com.mojang.serialization.Codec;
import com.mojang.serialization.JsonOps;

import dev.sam.common.net.StatusAdvert;
import dev.sam.server.SamServer;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.protocol.status.ClientboundStatusResponsePacket;
import net.minecraft.network.protocol.status.ServerStatus;

/**
 * La respuesta de estado lleva el campo {@code sam} (PROTOCOLO.md 2.4) cuando el login de SAM está
 * disponible. Se escribe igual que vanilla ({@code writeJsonWithCodec}), con el campo agregado.
 */
@Mixin(ClientboundStatusResponsePacket.class)
public abstract class StatusResponseMixin {

    @Redirect(method = "write", at = @At(value = "INVOKE",
        target = "Lnet/minecraft/network/FriendlyByteBuf;writeJsonWithCodec(Lcom/mojang/serialization/Codec;Ljava/lang/Object;)V"))
    private void sam$advertise(FriendlyByteBuf buf, Codec<ServerStatus> codec, Object status) {
        var json = codec.encodeStart(JsonOps.INSTANCE, (ServerStatus) status).getOrThrow();
        buf.writeUtf(StatusAdvert.render(json, SamServer.statusAdvert()));
    }
}
