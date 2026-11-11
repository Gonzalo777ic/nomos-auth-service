package com.nomos.inventory.auth.controller;

import com.nomos.inventory.auth.acl.LoginSession;
import com.nomos.inventory.auth.acl.MenuVisibilityService;
import com.nomos.inventory.auth.acl.SessionAuditService;
import com.nomos.inventory.auth.acl.dto.AccessSnapshotResponse;
import com.nomos.inventory.auth.acl.dto.LoginResponse;
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.service.UserServiceImpl;
import com.nomos.inventory.auth.util.JwtUtil;
import com.valeerp.kernel.DomainException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Registro y login. Login abre fila en el libro de sesiones y devuelve DTO (no entidad JPA).
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserServiceImpl userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final SessionAuditService sessionAuditService;
    private final MenuVisibilityService menuVisibilityService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody RegisterRequest request) {
        if (userService.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username is already taken!");
        }
        String email = request.getEmail() == null || request.getEmail().isBlank()
                ? request.getUsername()
                : request.getEmail();
        User user = User.registerLocal(request.getUsername(), email, request.getPassword());
        userService.saveUser(user);
        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest httpRequest
    ) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername())
                    .orElseThrow(() -> new DomainException("Usuario no encontrado"));

            AccessSnapshotResponse access = menuVisibilityService.accessSnapshot(user);
            String jwt = jwtUtil.generateToken(
                    userDetails.getUsername(),
                    userDetails.getAuthorities(),
                    access.getPermissions(),
                    access.getGroups(),
                    access.getMenus().stream().map(menu -> menu.getKey()).toList()
            );

            LoginSession session = sessionAuditService.openSession(
                    user.getId(),
                    user.getUsername(),
                    httpRequest.getRemoteAddr(),
                    httpRequest.getHeader("User-Agent")
            );

            return ResponseEntity.ok(new LoginResponse(jwt, session.getId(), access));
        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest().body("Invalid username or password");
        }
    }

    @PostMapping("/auth0-upsert")
    public ResponseEntity<String> auth0UpsertUser(@RequestBody Auth0UserRequest auth0UserRequest) {
        try {
            userService.findOrCreateAuth0User(
                    auth0UserRequest.getAuth0Id(),
                    auth0UserRequest.getEmail(),
                    auth0UserRequest.getRoles()
            );
            return ResponseEntity.ok("User upserted successfully in Nomos database.");
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Error processing user data: " + e.getMessage());
        }
    }

    public static class RegisterRequest {
        private String username;
        private String email;
        private String password;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}
