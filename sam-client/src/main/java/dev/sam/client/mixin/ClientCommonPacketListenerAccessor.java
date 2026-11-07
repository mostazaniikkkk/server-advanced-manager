package dev.sam.client.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

import net.minecraft.client.multiplayer.ClientCommonPacketListenerImpl;
import net.minecraft.network.Connection;

/**
 * La conexión de la fase configuration: en vanilla la atiende la ConnectScreen (tick y desconexión).
 * La AuthScreen la reemplaza, así que tiene que atenderla ella.
 */
@Mixin(ClientCommonPacketListenerImpl.class)
public interface ClientCommonPacketListenerAccessor {

    @Accessor("connection")
    Connection sam$connection();
}
