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
 * Maestro de puestos RRHH. Soft-delete. Unicidad activa (company_id, code).
 */
@Entity
@Table(name = "hr_positions")
public class Position extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(nullable = false, length = 180)
    private String name;

    protected Position() {
    }

    public static Position open(Long companyId, String code, String name) {
        Position position = new Position();
        position.bindCompany(companyId);
        position.rename(code, name);
        return position;
    }

    public void bindCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía del puesto es obligatoria");
        }
        this.companyId = companyId;
    }

    public void rename(String code, String name) {
        if (code == null || code.isBlank()) {
            throw new DomainException("El código del puesto es obligatorio");
        }
        if (name == null || name.isBlank()) {
            throw new DomainException("El nombre del puesto es obligatorio");
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
