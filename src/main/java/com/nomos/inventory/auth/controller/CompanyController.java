package com.nomos.inventory.auth.controller;

import com.nomos.inventory.auth.service.CompanyService;
import com.valeerp.kernel.company.dto.AssignMembershipRequest;
import com.valeerp.kernel.company.dto.ChangeMembershipRoleRequest;
import com.valeerp.kernel.company.dto.CompanyMembershipResponse;
import com.valeerp.kernel.company.dto.CompanyResponse;
import com.valeerp.kernel.company.dto.CreateCompanyRequest;
import com.valeerp.kernel.company.dto.UpdateCompanyRequest;
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
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Traduce HTTP ↔ DTOs. No expone entidades JPA ni contiene reglas de negocio.
 */
@RestController
@RequestMapping("/api/companies")
public class CompanyController {

    private final CompanyService companyService;

    public CompanyController(CompanyService companyService) {
        this.companyService = companyService;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CompanyResponse>> list() {
        return ResponseEntity.ok(companyService.listCompanies());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<CompanyResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(companyService.getCompany(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<CompanyResponse> create(@Valid @RequestBody CreateCompanyRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(companyService.createCompany(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<CompanyResponse> update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateCompanyRequest request
    ) {
        return ResponseEntity.ok(companyService.updateCompany(id, request));
    }

    /**
     * Dar de baja (soft-delete). No ejecuta DELETE SQL.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> retire(@PathVariable Long id) {
        companyService.retireCompany(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{companyId}/memberships")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CompanyMembershipResponse>> listMemberships(@PathVariable Long companyId) {
        return ResponseEntity.ok(companyService.listMemberships(companyId));
    }

    @GetMapping("/users/{userId}/memberships")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CompanyMembershipResponse>> listMembershipsByUser(
            @PathVariable Long userId
    ) {
        return ResponseEntity.ok(companyService.listMembershipsByUser(userId));
    }

    @PostMapping("/{companyId}/memberships")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<CompanyMembershipResponse> assignMembership(
            @PathVariable Long companyId,
            @Valid @RequestBody AssignMembershipRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(companyService.assignMembership(companyId, request));
    }

    @PutMapping("/{companyId}/memberships/{membershipId}/role")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<CompanyMembershipResponse> changeRole(
            @PathVariable Long companyId,
            @PathVariable Long membershipId,
            @Valid @RequestBody ChangeMembershipRoleRequest request
    ) {
        return ResponseEntity.ok(
                companyService.changeMembershipRole(companyId, membershipId, request.getRole())
        );
    }

    /**
     * Dar de baja la pertenencia (soft-delete). No ejecuta DELETE SQL.
     */
    @DeleteMapping("/{companyId}/memberships/{membershipId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> retireMembership(
            @PathVariable Long companyId,
            @PathVariable Long membershipId
    ) {
        companyService.retireMembership(companyId, membershipId);
        return ResponseEntity.noContent().build();
    }
}
