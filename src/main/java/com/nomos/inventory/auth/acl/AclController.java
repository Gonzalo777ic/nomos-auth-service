package com.nomos.inventory.auth.acl;

import com.nomos.inventory.auth.acl.dto.AccessSnapshotResponse;
import com.nomos.inventory.auth.acl.dto.CreatePermissionRequest;
import com.nomos.inventory.auth.acl.dto.CreateRoleRequest;
import com.nomos.inventory.auth.acl.dto.CreateSecurityGroupRequest;
import com.nomos.inventory.auth.acl.dto.MenuItemResponse;
import com.nomos.inventory.auth.acl.dto.PermissionResponse;
import com.nomos.inventory.auth.acl.dto.ReplacePermissionsRequest;
import com.nomos.inventory.auth.acl.dto.RoleResponse;
import com.nomos.inventory.auth.acl.dto.SecurityGroupResponse;
import com.nomos.inventory.auth.acl.dto.UserResponse;
import com.valeerp.kernel.Actors;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * API ACL + menús visibles. Solo DTOs; sin entidades JPA en la respuesta.
 */
@RestController
@RequestMapping("/api/auth/acl")
public class AclController {

    private final AclService aclService;
    private final MenuVisibilityService menuVisibilityService;

    public AclController(AclService aclService, MenuVisibilityService menuVisibilityService) {
        this.aclService = aclService;
        this.menuVisibilityService = menuVisibilityService;
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<PermissionResponse>> listPermissions() {
        return ResponseEntity.ok(aclService.listPermissions());
    }

    @PostMapping("/permissions")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<PermissionResponse> createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(aclService.createPermission(request));
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<RoleResponse>> listRoles() {
        return ResponseEntity.ok(aclService.listRoles());
    }

    @PostMapping("/roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<RoleResponse> createRole(@Valid @RequestBody CreateRoleRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(aclService.createRole(request));
    }

    @PutMapping("/roles/{roleId}/permissions")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<RoleResponse> replaceRolePermissions(
            @PathVariable Long roleId,
            @RequestBody ReplacePermissionsRequest request
    ) {
        return ResponseEntity.ok(aclService.replaceRolePermissions(roleId, request));
    }

    @DeleteMapping("/roles/{roleId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> retireRole(@PathVariable Long roleId) {
        aclService.retireRole(roleId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/security-groups")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<SecurityGroupResponse>> listGroups() {
        return ResponseEntity.ok(aclService.listGroups());
    }

    @PostMapping("/security-groups")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<SecurityGroupResponse> createGroup(@Valid @RequestBody CreateSecurityGroupRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(aclService.createGroup(request));
    }

    @PutMapping("/security-groups/{groupId}/permissions")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<SecurityGroupResponse> replaceGroupPermissions(
            @PathVariable Long groupId,
            @RequestBody ReplacePermissionsRequest request
    ) {
        return ResponseEntity.ok(aclService.replaceGroupPermissions(groupId, request));
    }

    @DeleteMapping("/security-groups/{groupId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> retireGroup(@PathVariable Long groupId) {
        aclService.retireGroup(groupId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/security-groups/{groupId}/users/{userId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<UserResponse> assignGroup(
            @PathVariable Long groupId,
            @PathVariable Long userId
    ) {
        return ResponseEntity.ok(UserResponse.from(aclService.assignGroupToUser(userId, groupId)));
    }

    @DeleteMapping("/security-groups/{groupId}/users/{userId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<UserResponse> revokeGroup(
            @PathVariable Long groupId,
            @PathVariable Long userId
    ) {
        return ResponseEntity.ok(UserResponse.from(aclService.revokeGroupFromUser(userId, groupId)));
    }

    @GetMapping("/menus")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<MenuItemResponse>> listMenus() {
        return ResponseEntity.ok(menuVisibilityService.listAllMenus());
    }

    @GetMapping("/menus/visible")
    public ResponseEntity<List<MenuItemResponse>> visibleMenus() {
        return ResponseEntity.ok(menuVisibilityService.visibleMenusForUsername(Actors.current()));
    }

    @GetMapping("/access")
    public ResponseEntity<AccessSnapshotResponse> accessSnapshot() {
        return ResponseEntity.ok(menuVisibilityService.accessSnapshot(Actors.current()));
    }
}
