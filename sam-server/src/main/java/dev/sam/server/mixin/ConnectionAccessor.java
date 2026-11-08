package dev.sam.server.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

import io.netty.channel.Channel;
import net.minecraft.network.Connection;

/** El canal de Netty de una conexión: ahí está la IP real resuelta en el ingreso (RS-WS-02). */
@Mixin(Connection.class)
public interface ConnectionAccessor {

    @Accessor("channel")
    Channel sam$channel();
}
