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
@RequestMapping("/api/auth/roles") // 🏆 URL BASE DEDICADA: /api/auth/roles
@RequiredArgsConstructor
public class RoleController {

    // Inyectamos el repositorio para acceder directamente a los datos de roles
    private final RoleRepository roleRepository;

    /**
     * Endpoint: GET /api/auth/roles
     * Obtiene una lista de todos los nombres de roles disponibles en el sistema.
     * Esta información es usada por el frontend (ej. en la lista de roles del UserForm).
     */
    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    // Nota: El permiso puede ser menos restrictivo si lo usan otros formularios.
    public ResponseEntity<List<String>> getAllRoleNames() {

        // 1. Obtener todos los objetos Role de la base de datos
        List<Role> roles = roleRepository.findAll();

        // 2. Mapear cada objeto Role a su nombre (String)
        List<String> roleNames = roles.stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        return ResponseEntity.ok(roleNames);
    }

    // Si fuera necesario, se podrían agregar aquí endpoints GET /roles/{name} o /roles/{id}
    // o un DTO más complejo que incluya la descripción del rol.
}