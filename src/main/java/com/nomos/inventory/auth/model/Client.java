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
    private Long id;

    @Column(unique = true, nullable = false)
    private String auth0Id;

    @Column(nullable = false)
    private String email;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    // --- Nuevos campos de facturación y contacto ---

    // NOTA: Es String simple por ahora (ver punto 2)
    @Column(name = "document_type", nullable = true)
    private String documentType;

    @Column(name = "document_number", nullable = true)
    private String documentNumber;

    @Column(name = "phone", nullable = true)
    private String phone;

    // La dirección puede ser nula si es una venta en tienda física
    @Column(name = "address", nullable = true)
    private String address;

    // Si quieres un flag para indicar si el perfil está completo
    // @Column(name = "is_profile_complete")
    // private Boolean isProfileComplete = false;
}