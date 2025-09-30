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
import org.springframework.security.core.Authentication; // Importación necesaria

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
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
}