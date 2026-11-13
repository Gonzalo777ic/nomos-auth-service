package com.valeerp.inventory.auth.controller;

import com.valeerp.hr.EmploymentContractService;
import com.valeerp.hr.dto.CancelBookRequest;
import com.valeerp.hr.dto.CompleteContractRequest;
import com.valeerp.hr.dto.ContractResponse;
import com.valeerp.hr.dto.CreateContractRequest;
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
 * Libro de contratos. Sin DELETE HTTP que borre filas: anular/completar por estado.
 */
@RestController
@RequestMapping("/api/hr/contracts")
public class EmploymentContractController {

    private final EmploymentContractService contractService;

    public EmploymentContractController(EmploymentContractService contractService) {
        this.contractService = contractService;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<ContractResponse>> list(
            @RequestParam(required = false) Long employeeId,
            @RequestParam(required = false) Long companyId
    ) {
        if (employeeId != null) {
            return ResponseEntity.ok(contractService.listByEmployee(employeeId));
        }
        if (companyId != null) {
            return ResponseEntity.ok(contractService.listByCompany(companyId));
        }
        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<ContractResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(contractService.get(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<ContractResponse> createDraft(@Valid @RequestBody CreateContractRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(contractService.createDraft(request));
    }

    @PostMapping("/{id}/activate")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<ContractResponse> activate(@PathVariable Long id) {
        return ResponseEntity.ok(contractService.activate(id));
    }

    @PostMapping("/{id}/complete")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<ContractResponse> complete(
            @PathVariable Long id,
            @RequestBody(required = false) CompleteContractRequest request
    ) {
        return ResponseEntity.ok(contractService.complete(id, request));
    }

    @PostMapping("/{id}/cancel")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<ContractResponse> cancel(
            @PathVariable Long id,
            @RequestBody(required = false) CancelBookRequest request
    ) {
        return ResponseEntity.ok(contractService.cancel(id, request));
    }
}
