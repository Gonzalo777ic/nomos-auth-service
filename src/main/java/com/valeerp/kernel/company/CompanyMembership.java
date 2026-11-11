package com.valeerp.kernel.company;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.SoftDeletable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Pertenencia de un usuario de identidad a una compañía (multi-company).
 * Guarda ids locales; no llama a otros servicios.
 * Unicidad activa (company_id, user_id) WHERE deleted_at IS NULL: índice parcial en BD.
 */
@Entity
@Table(name = "company_memberships")
public class CompanyMembership extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 32)
    private CompanyMembershipRole role;

    protected CompanyMembership() {
    }

    public static CompanyMembership assign(Long companyId, Long userId, CompanyMembershipRole role) {
        CompanyMembership membership = new CompanyMembership();
        membership.bind(companyId, userId);
        membership.changeRole(role);
        return membership;
    }

    public void bind(Long companyId, Long userId) {
        if (companyId == null) {
            throw new DomainException("La compañía de la pertenencia es obligatoria");
        }
        if (userId == null) {
            throw new DomainException("El usuario de la pertenencia es obligatorio");
        }
        this.companyId = companyId;
        this.userId = userId;
    }

    public void changeRole(CompanyMembershipRole role) {
        if (role == null) {
            throw new DomainException("El rol de pertenencia es obligatorio");
        }
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public Long getCompanyId() {
        return companyId;
    }

    public Long getUserId() {
        return userId;
    }

    public CompanyMembershipRole getRole() {
        return role;
    }
}
