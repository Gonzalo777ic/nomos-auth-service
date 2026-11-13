

package com.valeerp.inventory.auth.repository;

import com.valeerp.inventory.auth.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Long> {

    Optional<Client> findByAuth0Id(String auth0Id);
}