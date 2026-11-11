package com.valeerp.kernel.company.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Alta de compañía. Moneda y zona horaria son opcionales: si vienen vacías
 * se aplican los defaults de {@code valeerp.company.*}.
 */
public class CreateCompanyRequest {

    @NotBlank(message = "La razón social es obligatoria")
    @Size(max = 255)
    private String legalName;

    @Size(max = 8)
    private String currency;

    @Size(max = 64)
    private String timeZone;

    private Long ownerUserId;

    public String getLegalName() {
        return legalName;
    }

    public void setLegalName(String legalName) {
        this.legalName = legalName;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public String getTimeZone() {
        return timeZone;
    }

    public void setTimeZone(String timeZone) {
        this.timeZone = timeZone;
    }

    public Long getOwnerUserId() {
        return ownerUserId;
    }

    public void setOwnerUserId(Long ownerUserId) {
        this.ownerUserId = ownerUserId;
    }
}
