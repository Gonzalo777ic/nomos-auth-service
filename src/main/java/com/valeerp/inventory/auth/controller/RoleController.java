package com.valeerp.inventory.auth.controller;

import com.valeerp.inventory.auth.acl.dto.RoleResponse;
import com.valeerp.inventory.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Listado legacy de roles. Preferir {@code /api/auth/acl/roles} para permisos granulares.
 */
@RestController
@RequestMapping("/api/auth/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleRepository roleRepository;

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<RoleResponse>> getAllRoles() {
        List<RoleResponse> roles = roleRepository.findAll().stream()
                .map(RoleResponse::from)
                .toList();
        return ResponseEntity.ok(roles);
    }
}
