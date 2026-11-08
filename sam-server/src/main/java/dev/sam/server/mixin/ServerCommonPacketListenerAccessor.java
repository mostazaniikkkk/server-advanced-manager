package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

import net.minecraft.network.Connection;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;

/** La conexión de un listener del servidor: el login necesita la IP del cliente (RF-AUTH-06a). */
@Mixin(ServerCommonPacketListenerImpl.class)
public interface ServerCommonPacketListenerAccessor {

    @Accessor("connection")
    Connection sam$connection();
}
