// src/main/java/com/nomos/inventory/auth/model/Client.java

package com.nomos.inventory.auth.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "clients")
@Getter
@Setter
@NoArgsConstructor
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // ID de negocio del cliente

    // Columna para el ID de Auth0 (esencial para el JIT provisioning)
    @Column(unique = true, nullable = false)
    private String auth0Id;

    @Column(nullable = false)
    private String email; // El email del cliente

    // Atributos específicos del cliente (ej. la tienda web los necesita)
    @Column(name = "full_name")
    private String fullName;

    // Puedes omitir los roles aquí, ya que el rol ROLE_CLIENT está implícito.
    // Opcional: Atributos de negocio para la tienda (dirección, etc.)
    // private String shippingAddress;
}