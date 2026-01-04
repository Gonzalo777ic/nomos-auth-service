package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface UserService {
    User saveUser(User user);
    Optional<User> findByUsername(String username);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    Optional<Role> findByRoleName(String roleName);
    List<User> findUsersByRoleName(String roleName);
    List<User> findAllInternalUsers();

    void updateSupplierId(Long userId, Long supplierId);

    User findOrCreateAuth0User(String auth0Id, String email, Set<String> newRoleNamesFromAuth0);
}