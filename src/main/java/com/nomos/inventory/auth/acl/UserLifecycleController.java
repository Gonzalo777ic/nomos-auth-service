package com.nomos.inventory.auth.acl;

import com.nomos.inventory.auth.acl.dto.CreateUserRequest;
import com.nomos.inventory.auth.acl.dto.ReactivateByEmailRequest;
import com.nomos.inventory.auth.acl.dto.UserResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Ciclo de vida de usuarios de identidad: alta, baja lógica y reactivación.
 * Sin ficha comercial ni supplierId. No ejecuta DELETE SQL.
 */
@RestController
@RequestMapping("/api/auth/users")
public class UserLifecycleController {

    private final UserLifecycleService userLifecycleService;

    public UserLifecycleController(UserLifecycleService userLifecycleService) {
        this.userLifecycleService = userLifecycleService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<UserResponse>> list() {
        return ResponseEntity.ok(userLifecycleService.listUsers());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<UserResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(userLifecycleService.getUser(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<UserResponse> create(@Valid @RequestBody CreateUserRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userLifecycleService.createUser(request));
    }

    /**
     * Dar de baja (soft-delete). Conserva histórico; email queda libre por índice parcial.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<UserResponse> retire(@PathVariable Long id) {
        return ResponseEntity.ok(userLifecycleService.retireUser(id));
    }

    @PostMapping("/{id}/reactivate")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<UserResponse> reactivate(@PathVariable Long id) {
        return ResponseEntity.ok(userLifecycleService.reactivateUser(id));
    }

    @PostMapping("/reactivate-by-email")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<UserResponse> reactivateByEmail(@Valid @RequestBody ReactivateByEmailRequest request) {
        return ResponseEntity.ok(userLifecycleService.reactivateByEmail(request.getEmail()));
    }
}
