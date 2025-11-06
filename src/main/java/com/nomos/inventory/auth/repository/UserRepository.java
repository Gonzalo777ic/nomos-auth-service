package com.nomos.inventory.auth.repository;

import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.model.Role; // 💡 NUEVO: Importar Role
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List; // 💡 NUEVO: Importar List

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByAuth0Id(String auth0Id);

    // 💡 NUEVO: Método para encontrar usuarios que contengan un rol específico
    // Busca en la relación ManyToMany (campo 'roles' en el modelo User)
    List<User> findByRolesContaining(Role role);
}