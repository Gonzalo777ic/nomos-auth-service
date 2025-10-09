package com.nomos.inventory.auth.controller;

import lombok.Getter;
import lombok.Setter;

/**
 * Data Transfer Object (DTO) para recibir los datos básicos del usuario
 * de Auth0 (sub y email) que serán usados para el "upsert" en PostgreSQL.
 */
@Getter
@Setter
public class Auth0UserRequest {
    private String auth0Id; // El 'sub' del usuario de Auth0
    private String email;   // El correo electrónico (usado como username de la tienda)
    private String name;    // Opcional: Nombre completo
}
