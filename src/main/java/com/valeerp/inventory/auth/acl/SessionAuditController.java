package com.valeerp.inventory.auth.acl;

import com.valeerp.inventory.auth.acl.dto.LoginSessionResponse;
import com.valeerp.inventory.auth.acl.dto.VoidSessionRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Libro de sesiones: lectura y anulación. Sin DELETE físico ni soft-hide.
 */
@RestController
@RequestMapping("/api/auth/sessions")
public class SessionAuditController {

    private final SessionAuditService sessionAuditService;

    public SessionAuditController(SessionAuditService sessionAuditService) {
        this.sessionAuditService = sessionAuditService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<LoginSessionResponse>> list() {
        return ResponseEntity.ok(sessionAuditService.listSessions());
    }

    @GetMapping("/user/{userId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<LoginSessionResponse>> listByUser(@PathVariable Long userId) {
        return ResponseEntity.ok(sessionAuditService.listByUser(userId));
    }

    @PostMapping("/{sessionId}/void")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<LoginSessionResponse> voidSession(
            @PathVariable Long sessionId,
            @RequestBody(required = false) VoidSessionRequest request
    ) {
        return ResponseEntity.ok(sessionAuditService.voidSession(sessionId, request));
    }
}
