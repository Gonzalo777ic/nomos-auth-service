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

        return ResponseEntity.ok("Acceso concedido. Estás autenticado para la ruta /user.");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> adminEndpoint() {

        return ResponseEntity.ok("¡Acceso concedido! Eres un ROLE_ADMIN.");
    }

    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {

        return ResponseEntity.ok("Esta ruta es pública y no requiere autenticación.");
    }
}
