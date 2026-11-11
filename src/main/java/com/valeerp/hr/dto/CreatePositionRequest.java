package com.valeerp.hr.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class CreatePositionRequest {

    @NotNull(message = "La compañía es obligatoria")
    private Long companyId;

    @NotBlank(message = "El código es obligatorio")
    @Size(max = 64)
    private String code;

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 180)
    private String name;

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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
