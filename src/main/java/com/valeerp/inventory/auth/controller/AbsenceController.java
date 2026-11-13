package com.valeerp.inventory.auth.controller;

import com.valeerp.hr.AbsenceService;
import com.valeerp.hr.dto.AbsenceResponse;
import com.valeerp.hr.dto.CancelBookRequest;
import com.valeerp.hr.dto.CreateAbsenceRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Libro de ausencias. Sin DELETE físico: aprobar / completar / anular por estado.
 */
@RestController
@RequestMapping("/api/hr/absences")
public class AbsenceController {

    private final AbsenceService absenceService;

    public AbsenceController(AbsenceService absenceService) {
        this.absenceService = absenceService;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<AbsenceResponse>> list(
            @RequestParam(required = false) Long employeeId,
            @RequestParam(required = false) Long companyId
    ) {
        if (employeeId != null) {
            return ResponseEntity.ok(absenceService.listByEmployee(employeeId));
        }
        if (companyId != null) {
            return ResponseEntity.ok(absenceService.listByCompany(companyId));
        }
        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<AbsenceResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(absenceService.get(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<AbsenceResponse> createDraft(@Valid @RequestBody CreateAbsenceRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(absenceService.createDraft(request));
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<AbsenceResponse> approve(@PathVariable Long id) {
        return ResponseEntity.ok(absenceService.approve(id));
    }

    @PostMapping("/{id}/complete")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<AbsenceResponse> complete(@PathVariable Long id) {
        return ResponseEntity.ok(absenceService.complete(id));
    }

    @PostMapping("/{id}/cancel")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<AbsenceResponse> cancel(
            @PathVariable Long id,
            @RequestBody(required = false) CancelBookRequest request
    ) {
        return ResponseEntity.ok(absenceService.cancel(id, request));
    }
}
