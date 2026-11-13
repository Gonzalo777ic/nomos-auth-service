package com.valeerp.inventory.auth.controller;

import com.valeerp.inventory.auth.acl.dto.UserResponse;
import com.valeerp.inventory.auth.model.User;
import com.valeerp.inventory.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

/**
 * Consultas legacy de usuarios internos. Solo DTOs; sin supplierId ni ficha comercial.
 */
@RestController
@RequestMapping("/api/auth/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    public static class UserReferenceDTO {
        public Long id;
        public String name;

        public UserReferenceDTO(User user) {
            this.id = user.getId();
            this.name = user.getUsername();
        }
    }

    @GetMapping("/sellers")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_VENTAS', 'SCOPE_read:users')")
    public ResponseEntity<List<UserReferenceDTO>> getAllSellers() {
        List<User> sellers = userService.findUsersByRoleName("ROLE_ADMIN");
        List<UserReferenceDTO> dtoList = sellers.stream().map(UserReferenceDTO::new).toList();
        return ResponseEntity.ok(dtoList);
    }

    @GetMapping("/internal")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<UserResponse>> getAllInternalUsers() {
        List<UserResponse> dtoList = userService.findAllInternalUsers().stream()
                .map(UserResponse::from)
                .toList();
        return ResponseEntity.ok(dtoList);
    }

    @GetMapping("/info/{identifier}")
    public ResponseEntity<UserResponse> getUserInfo(@PathVariable String identifier) {
        Optional<User> userOpt = userService.findByAuth0Id(identifier);
        if (userOpt.isEmpty()) {
            userOpt = userService.findByUsername(identifier);
        }
        return userOpt
                .map(UserResponse::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
