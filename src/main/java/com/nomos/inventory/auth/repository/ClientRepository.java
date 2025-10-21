// src/main/java/com/nomos/inventory/auth/repository/ClientRepository.java

package com.nomos.inventory.auth.repository;

import com.nomos.inventory.auth.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Long> {
    // Método clave para el Provisioning JIT de Auth0
    Optional<Client> findByAuth0Id(String auth0Id);
}