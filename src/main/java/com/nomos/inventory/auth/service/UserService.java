package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import java.util.Optional;
import java.util.Set;
import java.util.List;

public interface UserService {
    User saveUser(User user);
    Optional<User> findByUsername(String username);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);

    // 1. Método EXISTENTE: Devuelve el Rol (Optional<Role>)
    Optional<Role> findByRoleName(String roleName); // Firma: findByRoleName(String)

    // 2. Método NUEVO (VENDEDORES): Devuelve la lista de Usuarios (List<User>)
    // 💡 Renombrado a findUsersByRoleName para evitar colisión
    List<User> findUsersByRoleName(String roleName); // Firma: findUsersByRoleName(String)

    // Método de autenticación existente
    User findOrCreateAuth0User(String auth0Id, String email, Set<String> roles);

    List<User> findAllInternalUsers();
}