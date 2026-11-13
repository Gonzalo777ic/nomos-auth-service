package com.valeerp.inventory.auth.controller;

import com.valeerp.hr.EmployeeService;
import com.valeerp.hr.dto.CreateEmployeeRequest;
import com.valeerp.hr.dto.EmployeeResponse;
import com.valeerp.hr.dto.LinkEmployeeUserRequest;
import com.valeerp.hr.dto.UpdateEmployeeRequest;
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

/**
 * Ficha RRHH. Distinta de User; el vínculo a identidad es solo {@code userId} opcional.
 */
@RestController
@RequestMapping("/api/hr/employees")
public class EmployeeController {

    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<EmployeeResponse>> list(@RequestParam Long companyId) {
        return ResponseEntity.ok(employeeService.listByCompany(companyId));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<EmployeeResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(employeeService.get(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<EmployeeResponse> create(@Valid @RequestBody CreateEmployeeRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(employeeService.create(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<EmployeeResponse> update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateEmployeeRequest request
    ) {
        return ResponseEntity.ok(employeeService.update(id, request));
    }

    @PutMapping("/{id}/user")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<EmployeeResponse> linkUser(
            @PathVariable Long id,
            @Valid @RequestBody LinkEmployeeUserRequest request
    ) {
        return ResponseEntity.ok(employeeService.linkUser(id, request));
    }

    @DeleteMapping("/{id}/user")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<EmployeeResponse> unlinkUser(@PathVariable Long id) {
        return ResponseEntity.ok(employeeService.unlinkUser(id));
    }

    /** Dar de baja (soft-delete). No ejecuta DELETE SQL. */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> retire(@PathVariable Long id) {
        employeeService.retire(id);
        return ResponseEntity.noContent().build();
    }
}
