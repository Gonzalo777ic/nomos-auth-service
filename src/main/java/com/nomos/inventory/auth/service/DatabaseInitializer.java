package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.acl.AclCatalogSeeder;
import com.nomos.inventory.auth.acl.SecurityGroup;
import com.nomos.inventory.auth.acl.SecurityGroupRepository;
import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.RoleEnum;
import com.nomos.inventory.auth.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Order(2)
public class DatabaseInitializer implements CommandLineRunner {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final SecurityGroupRepository securityGroupRepository;

    public DatabaseInitializer(
            UserService userService,
            PasswordEncoder passwordEncoder,
            SecurityGroupRepository securityGroupRepository
    ) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.securityGroupRepository = securityGroupRepository;
    }

    @Override
    public void run(String... args) {
        Role adminRole = userService.findByRoleName(RoleEnum.ROLE_ADMIN.name())
                .orElseThrow(() -> new IllegalStateException("Admin role not found after ACL seed."));

        if (userService.findByUsername("admin").isEmpty()) {
            User adminUser = User.registerLocal(
                    "admin",
                    "admin@valeerp.local",
                    passwordEncoder.encode("2577705")
            );
            adminUser.replaceRoles(Set.of(adminRole));
            securityGroupRepository.findByCode(AclCatalogSeeder.GROUP_SYSTEM)
                    .ifPresent(adminUser::assignSecurityGroup);
            userService.saveUser(adminUser);
            System.out.println("Initial admin user 'admin' created.");
        } else {
            userService.findByUsername("admin").ifPresent(admin -> {
                boolean changed = false;
                if (admin.getRoles().stream().noneMatch(role -> RoleEnum.ROLE_ADMIN.name().equals(role.getName()))) {
                    admin.assignRole(adminRole);
                    changed = true;
                }
                SecurityGroup system = securityGroupRepository.findByCode(AclCatalogSeeder.GROUP_SYSTEM).orElse(null);
                if (system != null && admin.getSecurityGroups().stream()
                        .noneMatch(group -> AclCatalogSeeder.GROUP_SYSTEM.equals(group.getCode()))) {
                    admin.assignSecurityGroup(system);
                    changed = true;
                }
                if (changed) {
                    userService.saveUser(admin);
                }
            });
            System.out.println("Admin user already exists. Skipping creation.");
        }
    }
}
