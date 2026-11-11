package com.nomos.inventory.auth.controller;

import com.valeerp.hr.PositionService;
import com.valeerp.hr.dto.CreatePositionRequest;
import com.valeerp.hr.dto.PositionResponse;
import com.valeerp.hr.dto.UpdatePositionRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/hr/positions")
public class PositionController {

    private final PositionService positionService;

    public PositionController(PositionService positionService) {
        this.positionService = positionService;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<PositionResponse>> list(@RequestParam Long companyId) {
        return ResponseEntity.ok(positionService.listByCompany(companyId));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<PositionResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(positionService.get(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<PositionResponse> create(@Valid @RequestBody CreatePositionRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(positionService.create(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<PositionResponse> update(
            @PathVariable Long id,
            @Valid @RequestBody UpdatePositionRequest request
    ) {
        return ResponseEntity.ok(positionService.update(id, request));
    }

    /** Dar de baja (soft-delete). No ejecuta DELETE SQL. */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> retire(@PathVariable Long id) {
        positionService.retire(id);
        return ResponseEntity.noContent().build();
    }
}
