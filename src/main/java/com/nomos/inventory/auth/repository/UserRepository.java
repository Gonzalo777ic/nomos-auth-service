package com.nomos.inventory.auth.repository;

import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.model.Role; 
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List; 

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByAuth0Id(String auth0Id);


    List<User> findByRolesContaining(Role role);
}