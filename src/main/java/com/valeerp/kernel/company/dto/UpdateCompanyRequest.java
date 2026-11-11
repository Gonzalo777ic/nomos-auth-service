package com.valeerp.kernel.company.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class UpdateCompanyRequest {

    @NotBlank(message = "La razón social es obligatoria")
    @Size(max = 255)
    private String legalName;

    @NotBlank(message = "La moneda es obligatoria")
    @Size(max = 8)
    private String currency;

    @NotBlank(message = "La zona horaria es obligatoria")
    @Size(max = 64)
    private String timeZone;

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
}
