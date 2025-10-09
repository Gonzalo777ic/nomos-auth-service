package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.RoleRepository;
import com.nomos.inventory.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jakarta.transaction.Transactional;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    // Métodos existentes de la interfaz UserService
    @Override
    public User saveUser(User user) {
        // Asegurar que la contraseña solo se encripte y guarde si no es un usuario Auth0
        if (user.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Role saveRole(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        Role role = roleRepository.findByName(roleName).orElseThrow(() -> new RuntimeException("Role not found"));

        Set<Role> roles = user.getRoles();
        if (roles == null) {
            roles = new HashSet<>();
        }
        roles.add(role);
        user.setRoles(roles);
        userRepository.save(user);
    }

    @Override
    public Optional<Role> findByRoleName(String roleName) {
        return roleRepository.findByName(roleName);
    }

    // Implementación del método findOrCreateAuth0User
    @Override
    public User findOrCreateAuth0User(String auth0Id, String email) {
        // ... (Tu lógica existente aquí) ...
        // 1. Intentar encontrar el usuario por su ID de Auth0
        Optional<User> existingUser = userRepository.findByAuth0Id(auth0Id);

        if (existingUser.isPresent()) {
            return existingUser.get();
        }

        // 2. Si no existe, crear un nuevo usuario
        User newUser = new User();
        newUser.setAuth0Id(auth0Id);
        newUser.setUsername(email);
        newUser.setPassword(null);

        // 3. Asignar el rol por defecto (Ahora el rol EXISTIRÁ)
        Role clientRole = roleRepository.findByName("ROLE_CLIENT")
                .orElseThrow(() -> new RuntimeException("Role ROLE_CLIENT not found in database."));

        newUser.setRoles(Collections.singleton(clientRole));

        // 4. Guardar el nuevo usuario en PostgreSQL
        return userRepository.save(newUser);
    }
}
