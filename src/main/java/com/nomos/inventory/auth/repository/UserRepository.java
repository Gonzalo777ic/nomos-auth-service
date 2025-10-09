package com.nomos.inventory.auth.repository;

import com.nomos.inventory.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    // NUEVO: Método para buscar por el ID de Auth0
    Optional<User> findByAuth0Id(String auth0Id);
}
