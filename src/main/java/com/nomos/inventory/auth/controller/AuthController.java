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

import com.nomos.inventory.auth.service.UserServiceImpl;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {


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

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            final UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            final String jwt = jwtUtil.generateToken(userDetails.getUsername(), userDetails.getAuthorities());

            return ResponseEntity.ok(jwt);

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

            System.err.println("Error saving/updating Auth0 user in database: " + e.getMessage());
            return ResponseEntity.internalServerError().body("Error processing user data: " + e.getMessage());
        }
    }

}
