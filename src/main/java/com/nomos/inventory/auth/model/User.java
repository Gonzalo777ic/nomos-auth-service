package com.nomos.inventory.auth.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Columna para el ID de Auth0 (el 'sub' del JWT)
    @Column(unique = true)
    private String auth0Id;

    @Column(unique = true, nullable = false)
    private String username; // Este campo puede seguir siendo el email

    // Hacemos que la contraseña sea opcional para usuarios de Auth0
    @Column(nullable = true)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles;
}
