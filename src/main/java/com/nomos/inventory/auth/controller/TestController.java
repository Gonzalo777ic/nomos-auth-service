package com.nomos.inventory.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador utilizado para verificar la funcionalidad del JWT Filter
 * y la autorización por roles definida en SecurityConfig.
 */
@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/user")
    public ResponseEntity<String> userEndpoint() {
        // Requiere solo autenticación (cualquier usuario con un token válido)
        return ResponseEntity.ok("Acceso concedido. Estás autenticado para la ruta /user.");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> adminEndpoint() {
        // Requiere el rol ROLE_ADMIN
        return ResponseEntity.ok("¡Acceso concedido! Eres un ROLE_ADMIN.");
    }

    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        // No requiere token (solo para demostrar que la ruta está abierta)
        return ResponseEntity.ok("Esta ruta es pública y no requiere autenticación.");
    }
}
