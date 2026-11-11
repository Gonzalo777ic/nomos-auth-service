package com.valeerp.hr.dto;

import com.valeerp.hr.Department;

public class DepartmentResponse {

    private final Long id;
    private final Long companyId;
    private final String code;
    private final String name;

    private DepartmentResponse(Long id, Long companyId, String code, String name) {
        this.id = id;
        this.companyId = companyId;
        this.code = code;
        this.name = name;
    }

    public static DepartmentResponse from(Department department) {
        return new DepartmentResponse(
                department.getId(),
                department.getCompanyId(),
                department.getCode(),
                department.getName()
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

    public String getName() {
        return name;
    }
}
