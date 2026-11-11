package com.valeerp.hr.dto;

import com.valeerp.hr.Employee;

import java.time.LocalDate;

public class EmployeeResponse {

    private final Long id;
    private final Long companyId;
    private final String code;
    private final String fullName;
    private final Long departmentId;
    private final Long positionId;
    private final Long userId;
    private final LocalDate hireDate;
    private final String workEmail;

    private EmployeeResponse(
            Long id,
            Long companyId,
            String code,
            String fullName,
            Long departmentId,
            Long positionId,
            Long userId,
            LocalDate hireDate,
            String workEmail
    ) {
        this.id = id;
        this.companyId = companyId;
        this.code = code;
        this.fullName = fullName;
        this.departmentId = departmentId;
        this.positionId = positionId;
        this.userId = userId;
        this.hireDate = hireDate;
        this.workEmail = workEmail;
    }

    public static EmployeeResponse from(Employee employee) {
        return new EmployeeResponse(
                employee.getId(),
                employee.getCompanyId(),
                employee.getCode(),
                employee.getFullName(),
                employee.getDepartmentId(),
                employee.getPositionId(),
                employee.getUserId(),
                employee.getHireDate(),
                employee.getWorkEmail()
        );
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
