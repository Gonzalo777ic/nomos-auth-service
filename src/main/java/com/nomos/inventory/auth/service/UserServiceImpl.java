package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.RoleRepository;
import com.nomos.inventory.auth.repository.UserRepository;
import com.nomos.inventory.auth.repository.ClientRepository;
import com.nomos.inventory.auth.model.Client;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j 
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ClientRepository clientRepository;

    @Override
    public User saveUser(User user) {
        if (user.getPassword() != null && !user.getPassword().startsWith("$2a$")) {
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

        if (user.getRoles() == null) {
            user.setRoles(new HashSet<>());
        }
        user.getRoles().add(role);
        userRepository.save(user);
    }

    @Override
    public Optional<Role> findByRoleName(String roleName) {
        return roleRepository.findByName(roleName);
    }

    @Override
    public List<User> findUsersByRoleName(String roleName) {
        return roleRepository.findByName(roleName)
                .map(userRepository::findByRolesContaining)
                .orElse(Collections.emptyList());
    }

    @Override
    public List<User> findAllInternalUsers() {
        Role clientRole = roleRepository.findByName("ROLE_CLIENT").orElse(null);
        List<User> allUsers = userRepository.findAll();
        if (clientRole == null) return allUsers;

        return allUsers.stream()
                .filter(user -> {
                    Set<Role> roles = user.getRoles();
                    if (roles == null || roles.isEmpty()) return true;
                    return !(roles.size() == 1 && roles.contains(clientRole));
                })
                .collect(Collectors.toList());
    }
    @Override
    @Transactional
    public void updateSupplierId(Long userId, Long supplierId) {
        userRepository.findById(userId).ifPresentOrElse(user -> {
            log.info("Asignando proveedor ID {} al usuario {}", supplierId, user.getUsername());
            user.setSupplierId(supplierId);
            userRepository.save(user);
        }, () -> {
            throw new RuntimeException("No se pudo encontrar el usuario con ID: " + userId);
        });
    }

    @Override
    @Transactional
    public User findOrCreateAuth0User(String auth0Id, String email, Set<String> newRoleNamesFromAuth0) {

        User user = userRepository.findByAuth0Id(auth0Id)
                .orElseGet(() -> userRepository.findByUsername(email).orElse(null));

        Set<Role> newRoles = getRolesFromNames(newRoleNamesFromAuth0);
        boolean hasInternalRole = newRoleNamesFromAuth0.stream()
                .anyMatch(roleName -> !roleName.equals("ROLE_CLIENT"));

        if (hasInternalRole) {
            if (user == null) {
                log.info("Provisioning JIT: Creando nuevo trabajador {}", email);
                user = new User();
                user.setAuth0Id(auth0Id);
                user.setUsername(email);
                user.setRoles(new HashSet<>());
            } else {
                user.setAuth0Id(auth0Id); 
            }

            syncRoles(user, newRoles);

            user = userRepository.saveAndFlush(user); 
            handleClientDemotion(auth0Id);
            return user;

        } else {
            handleClientProvisioning(auth0Id, email);
            handleUserDemotion(auth0Id);
            return null;
        }
    }


    private void syncRoles(User user, Set<Role> newRoles) {
        if (user.getRoles() == null) {
            user.setRoles(new HashSet<>());
        }

        if (user.getRoles().size() == newRoles.size() && user.getRoles().containsAll(newRoles)) {
            return;
        }

        log.info("Sincronizando roles para {}. Antes: {}. Después: {}",
                user.getUsername(),
                user.getRoles().stream().map(Role::getName).collect(Collectors.toList()),
                newRoles.stream().map(Role::getName).collect(Collectors.toList()));

        user.getRoles().clear();
        user.getRoles().addAll(newRoles);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void handleUserDemotion(String auth0Id) {
        userRepository.findByAuth0Id(auth0Id).ifPresent(user -> {
            log.warn("Democionando usuario interno {} a cliente.", auth0Id);
            userRepository.delete(user);
        });
    }

    @Transactional
    public void handleClientDemotion(String auth0Id) {
        clientRepository.findByAuth0Id(auth0Id).ifPresent(clientRepository::delete);
    }

    private Set<Role> getRolesFromNames(Set<String> roleNames) {
        return roleNames.stream()
                .map(name -> name.startsWith("ROLE_") ? name : "ROLE_" + name)
                .map(name -> roleRepository.findByName(name).orElse(null))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    public void handleClientProvisioning(String auth0Id, String email) {
        if (clientRepository.findByAuth0Id(auth0Id).isEmpty()) {
            Client newClient = new Client();
            newClient.setAuth0Id(auth0Id);
            newClient.setEmail(email);
            newClient.setFullName(email);
            clientRepository.save(newClient);
        }
    }

    @Override
    public Optional<User> findByAuth0Id(String auth0Id) {
        return userRepository.findByAuth0Id(auth0Id);
    }
}