package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.RoleRepository;
import com.nomos.inventory.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

// 🏆 ¡CORRECCIÓN CLAVE! Usar la anotación @Transactional de Spring
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.List;
import java.util.stream.Collectors;

import com.nomos.inventory.auth.repository.ClientRepository;
import com.nomos.inventory.auth.model.Client;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ClientRepository clientRepository;


    // --- Métodos de Gestión de Usuarios y Roles ---

    @Override
    public User saveUser(User user) {
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

    @Override
    public List<User> findUsersByRoleName(String roleName) {
        Optional<Role> roleOptional = findByRoleName(roleName);
        if (roleOptional.isPresent()) {
            Role role = roleOptional.get();
            return userRepository.findByRolesContaining(role);
        }
        return Collections.emptyList();
    }

    @Override
    public List<User> findAllInternalUsers() {
        Optional<Role> clientRoleOptional = findByRoleName("ROLE_CLIENT");
        if (clientRoleOptional.isEmpty()) {
            return userRepository.findAll();
        }
        final Role clientRole = clientRoleOptional.get();
        List<User> allUsers = userRepository.findAll();
        List<User> internalUsers = allUsers.stream()
                .filter(user -> {
                    Set<Role> roles = user.getRoles();
                    if (roles == null || roles.isEmpty()) {
                        return true;
                    }
                    return !(roles.size() == 1 && roles.contains(clientRole));
                })
                .collect(Collectors.toList());

        return internalUsers;
    }

    // --- Métodos de Provisioning JIT de Auth0 ---

    @Override
    @Transactional
    public User findOrCreateAuth0User(String auth0Id, String email, Set<String> newRoleNamesFromAuth0) {

        Optional<User> existingUser = userRepository.findByAuth0Id(auth0Id);
        User user = null;

        // Búsqueda Dual (Backfill)
        if (existingUser.isEmpty()) {
            Optional<User> existingUserByEmail = userRepository.findByUsername(email);
            if (existingUserByEmail.isPresent()) {
                user = existingUserByEmail.get();
                user.setAuth0Id(auth0Id);
                existingUser = Optional.of(user);
            }
        }

        // Si existe por Auth0Id, lo usamos
        if (existingUser.isPresent()) {
            user = existingUser.get();
        }


        Set<Role> newRoles = getRolesFromNames(newRoleNamesFromAuth0);

        // Lógica: ¿Tiene roles internos?
        boolean hasInternalRole = newRoleNamesFromAuth0.stream()
                .anyMatch(roleName -> !roleName.equals("ROLE_CLIENT"));


        if (hasInternalRole) {
            // Caso TRABAJADOR: Debe existir en la tabla 'users'

            if (user == null) {
                // CREACIÓN INICIAL como trabajador
                user = new User();
                user.setAuth0Id(auth0Id);
                user.setUsername(email);
                user.setPassword(null);
            }

            // SINCRONIZACIÓN de Roles
            if (user.getRoles() == null) {
                user.setRoles(new HashSet<>());
            }
            user.getRoles().clear();
            user.setRoles(newRoles);
            user = userRepository.save(user);

            // LIMPIEZA: Eliminamos de 'clients' si fue cliente antes
            handleClientDemotion(auth0Id);

        } else {
            // Caso CLIENTE PURO: No debe existir en 'users'

            // PROVISIÓN: Garantizamos que exista en 'clients'.
            handleClientProvisioning(auth0Id, email);

            // DEMOCIÓN CRÍTICA: Eliminamos de 'users' si existía. (Llama a transacción separada)
            handleUserDemotion(auth0Id);

            // Si es cliente puro, devolvemos null ya que no está en la tabla 'users'
            user = null;
        }

        return user;
    }

    // El @Transactional de Spring ahora permite usar Propagation
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void handleUserDemotion(String auth0Id) {
        System.out.println("🚨 Ejecutando handleUserDemotion en NUEVA transacción para Auth0 ID: " + auth0Id);

        Optional<User> existingUser = userRepository.findByAuth0Id(auth0Id);
        if (existingUser.isPresent()) {
            User user = existingUser.get();
            userRepository.delete(user);
            System.out.println("✅ Trabajador " + auth0Id + " democionado a cliente. Eliminada la entrada de la tabla users.");
        } else {
            System.out.println("ℹ️ Usuario Auth0 " + auth0Id + " no encontrado en la tabla users. No se requiere democión.");
        }
    }


    @Transactional
    public void handleClientDemotion(String auth0Id) {
        Optional<Client> existingClient = clientRepository.findByAuth0Id(auth0Id);
        if (existingClient.isPresent()) {
            Client client = existingClient.get();
            clientRepository.delete(client);
            System.out.println("Cliente " + auth0Id + " promovido a trabajador. Eliminada la entrada de la tabla clients.");
        }
    }

    private Set<Role> getRolesFromNames(Set<String> roleNames) {
        return roleNames.stream()
                .map(roleName -> findByRoleName(roleName).orElse(null))
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toSet());
    }

    public User handleClientProvisioning(String auth0Id, String email) {
        Optional<Client> existingClient = clientRepository.findByAuth0Id(auth0Id);

        if (existingClient.isPresent()) {
            System.out.println("Cliente ya existe en la BD. Provisioning JIT exitoso.");
            return null;
        }

        Client newClient = new Client();
        newClient.setAuth0Id(auth0Id);
        newClient.setEmail(email);
        newClient.setFullName(email);

        clientRepository.save(newClient);
        System.out.println("Nuevo Cliente creado en la BD. Provisioning JIT exitoso.");
        return null;
    }

    public User handleUserProvisioning(String auth0Id, String email, Set<String> roleNames) {
        Optional<User> existingUser = userRepository.findByAuth0Id(auth0Id);

        if (existingUser.isPresent()) {
            return existingUser.get();
        }

        User newUser = new User();
        newUser.setAuth0Id(auth0Id);
        newUser.setUsername(email);
        newUser.setPassword(null);

        Set<Role> roles = new HashSet<>();
        for (String roleName : roleNames) {
            roleRepository.findByName(roleName).ifPresent(roles::add);
        }

        if (roles.isEmpty()) {
            throw new RuntimeException("No se encontraron roles válidos en la BD para el usuario de Auth0.");
        }

        newUser.setRoles(roles);
        return userRepository.save(newUser);
    }
}