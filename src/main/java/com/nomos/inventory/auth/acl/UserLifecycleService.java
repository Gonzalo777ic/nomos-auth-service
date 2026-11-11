package com.nomos.inventory.auth.acl;

import com.nomos.inventory.auth.acl.dto.CreateUserRequest;
import com.nomos.inventory.auth.acl.dto.UserResponse;
import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.RoleRepository;
import com.nomos.inventory.auth.repository.UserRepository;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Alta, baja lógica y reactivación de usuarios de identidad.
 * Unicidad parcial de email/username vía índices SQL WHERE deleted_at IS NULL.
 */
@Service
public class UserLifecycleService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final SecurityGroupRepository securityGroupRepository;
    private final PasswordEncoder passwordEncoder;

    public UserLifecycleService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            SecurityGroupRepository securityGroupRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.securityGroupRepository = securityGroupRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public List<UserResponse> listUsers() {
        return userRepository.findAll().stream().map(UserResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public UserResponse getUser(Long id) {
        return UserResponse.from(requireActive(id));
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        String email = request.getEmail().trim().toLowerCase();
        String username = request.getUsername().trim();
        if (userRepository.existsByEmail(email)) {
            throw new DomainException("Ya existe un usuario activo con ese email");
        }
        if (userRepository.existsByUsername(username)) {
            throw new DomainException("Ya existe un usuario activo con ese username");
        }
        User user = User.registerLocal(username, email, passwordEncoder.encode(request.getPassword()));
        user.replaceRoles(resolveRoles(request.getRoleNames()));
        for (String groupCode : request.getGroupCodes()) {
            SecurityGroup group = securityGroupRepository.findByCode(groupCode.trim().toLowerCase())
                    .orElseThrow(() -> new DomainException("Grupo no encontrado: " + groupCode));
            user.assignSecurityGroup(group);
        }
        return UserResponse.from(userRepository.save(user));
    }

    @Transactional
    public UserResponse retireUser(Long id) {
        User user = requireActive(id);
        user.retire(Actors.current(), Instant.now());
        return UserResponse.from(userRepository.save(user));
    }

    /**
     * Reactiva un usuario dado de baja (mismo email reutilizable por índice parcial).
     */
    @Transactional
    public UserResponse reactivateUser(Long id) {
        Long retiredId = userRepository.findRetiredIdById(id)
                .orElseThrow(() -> new DomainException("El usuario no está dado de baja o no existe"));
        String email = userRepository.findRetiredEmailById(retiredId)
                .orElseThrow(() -> new DomainException("Email del usuario dado de baja no encontrado"));
        String username = userRepository.findRetiredUsernameById(retiredId)
                .orElseThrow(() -> new DomainException("Username del usuario dado de baja no encontrado"));
        if (userRepository.existsByEmail(email)) {
            throw new DomainException("Ya existe un usuario activo con ese email");
        }
        if (userRepository.existsByUsername(username)) {
            throw new DomainException("Ya existe un usuario activo con ese username");
        }
        int updated = userRepository.clearSoftDelete(retiredId);
        if (updated != 1) {
            throw new DomainException("No se pudo reactivar el usuario");
        }
        User restored = userRepository.findById(retiredId)
                .orElseThrow(() -> new DomainException("Usuario no encontrado tras reactivar"));
        return UserResponse.from(restored);
    }

    @Transactional
    public UserResponse reactivateByEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new DomainException("El email es obligatorio");
        }
        Long retiredId = userRepository.findRetiredIdByEmail(email.trim().toLowerCase())
                .orElseThrow(() -> new DomainException("No hay usuario dado de baja con ese email"));
        return reactivateUser(retiredId);
    }

    private User requireActive(Long id) {
        if (id == null) {
            throw new DomainException("El usuario es obligatorio");
        }
        return userRepository.findById(id)
                .orElseThrow(() -> new DomainException("Usuario no encontrado"));
    }

    private Set<Role> resolveRoles(List<String> roleNames) {
        Set<Role> roles = new HashSet<>();
        if (roleNames == null) {
            return roles;
        }
        for (String raw : roleNames) {
            String name = raw.trim().toUpperCase();
            if (!name.startsWith("ROLE_")) {
                name = "ROLE_" + name;
            }
            String roleName = name;
            Role role = roleRepository.findByName(roleName)
                    .orElseThrow(() -> new DomainException("Rol no encontrado: " + roleName));
            roles.add(role);
        }
        return roles;
    }
}
