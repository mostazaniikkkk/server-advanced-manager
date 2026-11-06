package dev.sam.client.net;

/** Lo que el mixin agrega a {@code Connection}: si esta conexión va por el TLS de SAM y a dónde. */
public interface SamTlsConnection {

    void sam$setPlan(SamClientNet.Plan plan);

    SamClientNet.Plan sam$plan();
}
