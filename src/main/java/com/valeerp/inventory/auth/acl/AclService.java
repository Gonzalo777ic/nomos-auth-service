package com.valeerp.inventory.auth.acl;

import com.valeerp.inventory.auth.acl.dto.CreatePermissionRequest;
import com.valeerp.inventory.auth.acl.dto.CreateRoleRequest;
import com.valeerp.inventory.auth.acl.dto.CreateSecurityGroupRequest;
import com.valeerp.inventory.auth.acl.dto.PermissionResponse;
import com.valeerp.inventory.auth.acl.dto.ReplacePermissionsRequest;
import com.valeerp.inventory.auth.acl.dto.RoleResponse;
import com.valeerp.inventory.auth.acl.dto.SecurityGroupResponse;
import com.valeerp.inventory.auth.model.Role;
import com.valeerp.inventory.auth.model.User;
import com.valeerp.inventory.auth.repository.RoleRepository;
import com.valeerp.inventory.auth.repository.UserRepository;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Casos de uso ACL: permisos, roles y grupos de seguridad.
 * No expone entidades JPA ni posee ficha comercial.
 */
@Service
public class AclService {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final SecurityGroupRepository securityGroupRepository;
    private final UserRepository userRepository;

    public AclService(
            PermissionRepository permissionRepository,
            RoleRepository roleRepository,
            SecurityGroupRepository securityGroupRepository,
            UserRepository userRepository
    ) {
        this.permissionRepository = permissionRepository;
        this.roleRepository = roleRepository;
        this.securityGroupRepository = securityGroupRepository;
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> listPermissions() {
        return permissionRepository.findAll().stream().map(PermissionResponse::from).toList();
    }

    @Transactional
    public PermissionResponse createPermission(CreatePermissionRequest request) {
        ErpApp app = ErpApp.require(request.getApp());
        AclAction action = AclAction.require(request.getAction());
        Permission permission = Permission.define(app, request.getModel(), action, request.getDescription());
        if (permissionRepository.existsByCode(permission.getCode())) {
            throw new DomainException("Ya existe el permiso " + permission.getCode());
        }
        return PermissionResponse.from(permissionRepository.save(permission));
    }

    @Transactional(readOnly = true)
    public List<RoleResponse> listRoles() {
        return roleRepository.findAll().stream().map(RoleResponse::from).toList();
    }

    @Transactional
    public RoleResponse createRole(CreateRoleRequest request) {
        Role role = Role.define(request.getName(), request.getDescription());
        if (roleRepository.findByName(role.getName()).isPresent()) {
            throw new DomainException("Ya existe el rol " + role.getName());
        }
        role.replacePermissions(resolvePermissions(request.getPermissionCodes()));
        return RoleResponse.from(roleRepository.save(role));
    }

    @Transactional
    public RoleResponse replaceRolePermissions(Long roleId, ReplacePermissionsRequest request) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new DomainException("Rol no encontrado"));
        role.replacePermissions(resolvePermissions(request.getPermissionCodes()));
        return RoleResponse.from(roleRepository.save(role));
    }

    @Transactional
    public void retireRole(Long roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new DomainException("Rol no encontrado"));
        role.retire(Actors.current(), Instant.now());
        roleRepository.save(role);
    }

    @Transactional(readOnly = true)
    public List<SecurityGroupResponse> listGroups() {
        return securityGroupRepository.findAll().stream().map(SecurityGroupResponse::from).toList();
    }

    @Transactional
    public SecurityGroupResponse createGroup(CreateSecurityGroupRequest request) {
        if (securityGroupRepository.existsByCode(request.getCode().trim().toLowerCase())) {
            throw new DomainException("Ya existe el grupo " + request.getCode());
        }
        SecurityGroup group = SecurityGroup.define(request.getCode(), request.getName(), request.getDescription());
        group.replacePermissions(resolvePermissions(request.getPermissionCodes()));
        return SecurityGroupResponse.from(securityGroupRepository.save(group));
    }

    @Transactional
    public SecurityGroupResponse replaceGroupPermissions(Long groupId, ReplacePermissionsRequest request) {
        SecurityGroup group = requireGroup(groupId);
        group.replacePermissions(resolvePermissions(request.getPermissionCodes()));
        return SecurityGroupResponse.from(securityGroupRepository.save(group));
    }

    @Transactional
    public void retireGroup(Long groupId) {
        SecurityGroup group = requireGroup(groupId);
        group.retire(Actors.current(), Instant.now());
        securityGroupRepository.save(group);
    }

    @Transactional
    public User assignGroupToUser(Long userId, Long groupId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new DomainException("Usuario no encontrado"));
        SecurityGroup group = requireGroup(groupId);
        user.assignSecurityGroup(group);
        return userRepository.save(user);
    }

    @Transactional
    public User revokeGroupFromUser(Long userId, Long groupId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new DomainException("Usuario no encontrado"));
        SecurityGroup group = requireGroup(groupId);
        user.revokeSecurityGroup(group);
        return userRepository.save(user);
    }

    private SecurityGroup requireGroup(Long groupId) {
        if (groupId == null) {
            throw new DomainException("El grupo es obligatorio");
        }
        return securityGroupRepository.findById(groupId)
                .orElseThrow(() -> new DomainException("Grupo de seguridad no encontrado"));
    }

    private Set<Permission> resolvePermissions(List<String> codes) {
        if (codes == null || codes.isEmpty()) {
            return Set.of();
        }
        Set<Permission> resolved = new HashSet<>();
        for (String code : codes) {
            Permission permission = permissionRepository.findByCode(code.trim().toLowerCase())
                    .orElseThrow(() -> new DomainException("Permiso no encontrado: " + code));
            resolved.add(permission);
        }
        return resolved;
    }
}
