package com.valeerp.hr;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.SoftDeletable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDate;

/**
 * Ficha RRHH distinta de {@code User} de identidad.
 * Vínculo opcional a identidad solo por {@code userId} (sin ficha comercial).
 * Soft-delete; unicidad activa (company_id, code) WHERE deleted_at IS NULL.
 */
@Entity
@Table(name = "hr_employees")
public class Employee extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(name = "full_name", nullable = false, length = 255)
    private String fullName;

    @Column(name = "department_id", nullable = false)
    private Long departmentId;

    @Column(name = "position_id", nullable = false)
    private Long positionId;

    /**
     * Id de User de identidad. Opcional; nunca posee email comercial ni partner.
     */
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "hire_date", nullable = false)
    private LocalDate hireDate;

    @Column(name = "work_email", length = 180)
    private String workEmail;

    protected Employee() {
    }

    public static Employee hire(
            Long companyId,
            String code,
            String fullName,
            Long departmentId,
            Long positionId,
            LocalDate hireDate,
            Long userId,
            String workEmail
    ) {
        Employee employee = new Employee();
        employee.bindCompany(companyId);
        employee.reassignOrg(departmentId, positionId);
        employee.rename(code, fullName);
        employee.changeHireDate(hireDate);
        employee.linkUser(userId);
        employee.changeWorkEmail(workEmail);
        return employee;
    }

    public void bindCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía del empleado es obligatoria");
        }
        this.companyId = companyId;
    }

    public void rename(String code, String fullName) {
        if (code == null || code.isBlank()) {
            throw new DomainException("El código del empleado es obligatorio");
        }
        if (fullName == null || fullName.isBlank()) {
            throw new DomainException("El nombre del empleado es obligatorio");
        }
        this.code = code.trim().toUpperCase();
        this.fullName = fullName.trim();
    }

    public void reassignOrg(Long departmentId, Long positionId) {
        if (departmentId == null) {
            throw new DomainException("El departamento es obligatorio");
        }
        if (positionId == null) {
            throw new DomainException("El puesto es obligatorio");
        }
        this.departmentId = departmentId;
        this.positionId = positionId;
    }

    public void changeHireDate(LocalDate hireDate) {
        if (hireDate == null) {
            throw new DomainException("La fecha de ingreso es obligatoria");
        }
        this.hireDate = hireDate;
    }

    public void linkUser(Long userId) {
        this.userId = userId;
    }

    public void unlinkUser() {
        this.userId = null;
    }

    public void changeWorkEmail(String workEmail) {
        this.workEmail = workEmail == null || workEmail.isBlank() ? null : workEmail.trim().toLowerCase();
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

    public String getFullName() {
        return fullName;
    }

    public Long getDepartmentId() {
        return departmentId;
    }

    public Long getPositionId() {
        return positionId;
    }

    public Long getUserId() {
        return userId;
    }

    public LocalDate getHireDate() {
        return hireDate;
    }

    public String getWorkEmail() {
        return workEmail;
    }
}
