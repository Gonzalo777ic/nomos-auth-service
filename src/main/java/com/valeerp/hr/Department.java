package com.valeerp.hr;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.SoftDeletable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Maestro organizativo RRHH. Soft-delete; no es ficha comercial ni User.
 * Unicidad activa (company_id, code) WHERE deleted_at IS NULL: índice parcial.
 */
@Entity
@Table(name = "hr_departments")
public class Department extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(nullable = false, length = 180)
    private String name;

    protected Department() {
    }

    public static Department open(Long companyId, String code, String name) {
        Department department = new Department();
        department.bindCompany(companyId);
        department.rename(code, name);
        return department;
    }

    public void bindCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía del departamento es obligatoria");
        }
        this.companyId = companyId;
    }

    public void rename(String code, String name) {
        if (code == null || code.isBlank()) {
            throw new DomainException("El código del departamento es obligatorio");
        }
        if (name == null || name.isBlank()) {
            throw new DomainException("El nombre del departamento es obligatorio");
        }
        this.code = code.trim().toUpperCase();
        this.name = name.trim();
    }

    public Long getId() {
        return id;
    }

    public Long getCompanyId() {
        return companyId;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }
}
