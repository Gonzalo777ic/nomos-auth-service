package com.nomos.inventory.auth.controller;

import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.service.AuthUserDetailsService;
import com.nomos.inventory.auth.service.UserService;
import com.nomos.inventory.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;

// IMPORTACIÓN FALTANTE
import com.nomos.inventory.auth.service.UserServiceImpl;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    // Se cambió de UserService a UserServiceImpl para acceder a findOrCreateAuth0User
    // o deberías agregarlo a la interfaz UserService (ver abajo)
    private final UserServiceImpl userService;
    private final AuthenticationManager authenticationManager;
    private final AuthUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        if (userService.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username is already taken!");
        }
        userService.saveUser(user);
        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest) {
        try {
            // Paso 1: Autenticar y obtener el objeto Authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            // Paso 2: Obtener los detalles del usuario, que ahora incluyen los roles
            final UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Paso 3: Generar el JWT con el username y las autoridades (roles)
            final String jwt = jwtUtil.generateToken(userDetails.getUsername(), userDetails.getAuthorities());

            return ResponseEntity.ok(jwt);

        } catch (AuthenticationException e) {
            // Maneja específicamente las excepciones de autenticación
            return ResponseEntity.badRequest().body("Invalid username or password");
        }
    }

    // El 'Auth0UserRequest' ahora debería ser resuelto gracias al nuevo archivo.
    @PostMapping("/auth0-upsert")
    public ResponseEntity<String> auth0UpsertUser(@RequestBody Auth0UserRequest auth0UserRequest) {
        try {
            // Lógica para encontrar o crear el usuario en la BD de la tienda
            // 🛑 AÑADIR EL TERCER ARGUMENTO: roles
            userService.findOrCreateAuth0User(
                    auth0UserRequest.getAuth0Id(),
                    auth0UserRequest.getEmail(),
                    auth0UserRequest.getRoles() // 🛑 EL TERCER ARGUMENTO AÑADIDO
            );
            return ResponseEntity.ok("User upserted successfully in Nomos database.");
        } catch (Exception e) {
            // Manejar errores si el rol ROLE_CLIENT no existe, por ejemplo.
            System.err.println("Error saving/updating Auth0 user in database: " + e.getMessage());
            return ResponseEntity.internalServerError().body("Error processing user data: " + e.getMessage());
        }
    }

}
