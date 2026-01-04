package com.nomos.inventory.auth.controller;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth/roles") 
@RequiredArgsConstructor
public class RoleController {

    private final RoleRepository roleRepository;

    /**
     * Endpoint: GET /api/auth/roles
     * Obtiene una lista de todos los nombres de roles disponibles en el sistema.
     * Esta información es usada por el frontend (ej. en la lista de roles del UserForm).
     */
    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")

    public ResponseEntity<List<String>> getAllRoleNames() {

        List<Role> roles = roleRepository.findAll();

        List<String> roleNames = roles.stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        return ResponseEntity.ok(roleNames);
    }


}