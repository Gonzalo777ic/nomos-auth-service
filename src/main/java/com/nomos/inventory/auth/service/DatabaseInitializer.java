package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.RoleEnum; 
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
public class DatabaseInitializer implements CommandLineRunner {

    private final UserService userService;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public DatabaseInitializer(UserService userService, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {



        Arrays.stream(RoleEnum.values()).forEach(roleEnum -> {
            String roleName = roleEnum.name();
            userService.findByRoleName(roleName).ifPresentOrElse(
                    role -> {


                    },
                    () -> {

                        Role newRole = new Role();
                        newRole.setName(roleName);
                        roleRepository.save(newRole);
                        System.out.println("Role '" + roleName + "' created from enum.");
                    }
            );
        });




        Role adminRole = userService.findByRoleName(RoleEnum.ROLE_ADMIN.name())
                .orElseThrow(() -> new IllegalStateException("Admin role not found after initialization."));



        if (userService.findByUsername("admin").isEmpty()) {
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setPassword(passwordEncoder.encode("2577705"));

            Set<Role> roles = new HashSet<>();
            roles.add(adminRole);
            adminUser.setRoles(roles);

            userService.saveUser(adminUser);
            System.out.println("Initial admin user 'admin' created.");
        } else {
            System.out.println("Admin user already exists. Skipping creation.");
        }
    }
}