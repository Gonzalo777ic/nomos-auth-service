package com.nomos.inventory.auth.controller;

import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * DTO para la gestión de usuarios internos.
     *  CORRECCIÓN: Se añadió el campo 'supplierId' para que el Frontend
     * pueda filtrar los usuarios vinculados a cada proveedor.
     */
    public static class InternalUserDTO {
        public Long id;
        public String username;
        public String auth0Id;
        public List<String> roles;
        public Long supplierId; 

        public InternalUserDTO(User user) {
            this.id = user.getId();
            this.username = user.getUsername();
            this.auth0Id = user.getAuth0Id();
            this.supplierId = user.getSupplierId(); 
            this.roles = user.getRoles().stream()
                    .map(role -> role.getName())
                    .collect(Collectors.toList());
        }
    }

    /**
     * DTO simple para referencias rápidas (ej: selectores de vendedores).
     */
    public static class UserReferenceDTO {
        public Long id;
        public String name;

        public UserReferenceDTO(User user) {
            this.id = user.getId();
            this.name = user.getUsername();
        }
    }

    /**
     * Endpoint: GET /api/auth/users/sellers
     * Obtiene usuarios con roles de venta/administración.
     */
    @GetMapping("/sellers")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_VENTAS', 'SCOPE_read:users')")
    public ResponseEntity<List<UserReferenceDTO>> getAllSellers() {

        List<User> sellers = userService.findUsersByRoleName("ROLE_ADMIN");

        List<UserReferenceDTO> dtoList = sellers.stream()
                .map(UserReferenceDTO::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(dtoList);
    }

    /**
     * Endpoint: GET /api/auth/users/internal
     * Devuelve la lista completa de trabajadores con sus roles y vinculación a proveedores.
     */
    @GetMapping("/internal")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<InternalUserDTO>> getAllInternalUsers() {
        List<User> internalUsers = userService.findAllInternalUsers();

        List<InternalUserDTO> dtoList = internalUsers.stream()
                .map(InternalUserDTO::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(dtoList);
    }

    /**
     * Endpoint: PATCH /api/auth/users/{id}/supplier
     * Permite vincular o desvincular (si supplierId es null) un usuario a una empresa proveedora.
     */
    @PatchMapping("/{id}/supplier")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> updateSupplierAssignment(
            @PathVariable Long id,
            @RequestParam(required = false) Long supplierId) {

        try {
            userService.updateSupplierId(id, supplierId);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    @GetMapping("/info/{identifier}")
    public ResponseEntity<InternalUserDTO> getUserInfo(@PathVariable String identifier) {

        Optional<User> userOpt = userService.findByAuth0Id(identifier);

        if (userOpt.isEmpty()) {
            userOpt = userService.findByUsername(identifier);
        }

        return userOpt
                .map(InternalUserDTO::new)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

}