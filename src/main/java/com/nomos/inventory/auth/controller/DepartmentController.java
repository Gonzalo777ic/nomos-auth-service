package com.nomos.inventory.auth.controller;

import com.valeerp.hr.DepartmentService;
import com.valeerp.hr.dto.CreateDepartmentRequest;
import com.valeerp.hr.dto.DepartmentResponse;
import com.valeerp.hr.dto.UpdateDepartmentRequest;
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
@RequestMapping("/api/hr/departments")
public class DepartmentController {

    private final DepartmentService departmentService;

    public DepartmentController(DepartmentService departmentService) {
        this.departmentService = departmentService;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<DepartmentResponse>> list(@RequestParam Long companyId) {
        return ResponseEntity.ok(departmentService.listByCompany(companyId));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<DepartmentResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(departmentService.get(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<DepartmentResponse> create(@Valid @RequestBody CreateDepartmentRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(departmentService.create(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<DepartmentResponse> update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateDepartmentRequest request
    ) {
        return ResponseEntity.ok(departmentService.update(id, request));
    }

    /** Dar de baja (soft-delete). No ejecuta DELETE SQL. */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> retire(@PathVariable Long id) {
        departmentService.retire(id);
        return ResponseEntity.noContent().build();
    }
}
