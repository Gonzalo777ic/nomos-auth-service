package com.valeerp.hr.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public class CreateEmployeeRequest {

    @NotNull(message = "La compañía es obligatoria")
    private Long companyId;

    @NotBlank(message = "El código es obligatorio")
    @Size(max = 64)
    private String code;

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 255)
    private String fullName;

    @NotNull(message = "El departamento es obligatorio")
    private Long departmentId;

    @NotNull(message = "El puesto es obligatorio")
    private Long positionId;

    /** Vínculo opcional a User de identidad (solo id). */
    private Long userId;

    @NotNull(message = "La fecha de ingreso es obligatoria")
    private LocalDate hireDate;

    @Size(max = 180)
    private String workEmail;

    public Long getCompanyId() {
        return companyId;
    }

    public void setCompanyId(Long companyId) {
        this.companyId = companyId;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public Long getDepartmentId() {
        return departmentId;
    }

    public void setDepartmentId(Long departmentId) {
        this.departmentId = departmentId;
    }

    public Long getPositionId() {
        return positionId;
    }

    public void setPositionId(Long positionId) {
        this.positionId = positionId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public LocalDate getHireDate() {
        return hireDate;
    }

    public void setHireDate(LocalDate hireDate) {
        this.hireDate = hireDate;
    }

    public String getWorkEmail() {
        return workEmail;
    }

    public void setWorkEmail(String workEmail) {
        this.workEmail = workEmail;
    }
}
