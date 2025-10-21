// src/main/java/com/nomos/inventory/auth/service/UserService.java

package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import java.util.Optional;
import java.util.Set; // 🛑 Importar Set

public interface UserService {
    User saveUser(User user);
    Optional<User> findByUsername(String username);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    Optional<Role> findByRoleName(String roleName);

    // 🛑 Modificar la firma para incluir el Set<String> roles
    User findOrCreateAuth0User(String auth0Id, String email, Set<String> roles);
}