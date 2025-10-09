package com.nomos.inventory.auth.service; // PAQUETE CORREGIDO

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.RoleRepository;
import com.nomos.inventory.auth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Component
public class DatabaseInitializer implements CommandLineRunner {

    // Cambiamos las inyecciones directas a inyecciones del servicio para consistencia
    private final UserService userService;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    // Ajustamos el constructor para usar UserService
    public DatabaseInitializer(UserService userService, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Step 1: Check if "ROLE_ADMIN" exists and create it if not
        Optional<Role> adminRoleOptional = userService.findByRoleName("ROLE_ADMIN");
        Role adminRole;
        if (adminRoleOptional.isEmpty()) {
            adminRole = new Role();
            adminRole.setName("ROLE_ADMIN");
            roleRepository.save(adminRole);
            System.out.println("Role 'ROLE_ADMIN' created.");
        } else {
            adminRole = adminRoleOptional.get();
        }

        // Step 1.1: Check if "ROLE_CLIENT" exists and create it if not
        // AÑADIDO: El rol que Auth0 usará por defecto.
        Optional<Role> clientRoleOptional = userService.findByRoleName("ROLE_CLIENT");
        if (clientRoleOptional.isEmpty()) {
            Role clientRole = new Role();
            clientRole.setName("ROLE_CLIENT");
            roleRepository.save(clientRole);
            System.out.println("Role 'ROLE_CLIENT' created.");
        }

        // Step 2: Check if the admin user exists and create it if not
        if (userService.findByUsername("admin").isEmpty()) {
            User adminUser = new User();
            adminUser.setUsername("admin");
            // Usamos la contraseña codificada
            adminUser.setPassword(passwordEncoder.encode("2577705"));
            // Eliminamos la línea adminUser.setEmail("admin@nomos.com"); para evitar el error 'Cannot resolve method setEmail'

            Set<Role> roles = new HashSet<>();
            roles.add(adminRole);
            adminUser.setRoles(roles);

            // Guardamos usando el servicio
            userService.saveUser(adminUser);
            System.out.println("Initial admin user 'admin' created.");
        } else {
            System.out.println("Admin user already exists. Skipping creation.");
        }
    }
}
