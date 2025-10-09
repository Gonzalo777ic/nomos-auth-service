package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.model.Role;
import java.util.Optional;

public interface UserService {
    User saveUser(User user);
    Optional<User> findByUsername(String username);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);

    // Declaración del método de persistencia de Auth0
    User findOrCreateAuth0User(String auth0Id, String email);

    // NUEVO: Método para buscar roles por nombre (usado por DatabaseInitializer)
    Optional<Role> findByRoleName(String roleName);
}
