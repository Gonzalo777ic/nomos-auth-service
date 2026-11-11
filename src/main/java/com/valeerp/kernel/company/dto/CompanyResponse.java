package com.valeerp.kernel.company.dto;

import com.valeerp.kernel.company.Company;

public class CompanyResponse {

    private final Long id;
    private final String legalName;
    private final String currency;
    private final String timeZone;
    private final String timeZoneId;

    private CompanyResponse(Long id, String legalName, String currency, String timeZone, String timeZoneId) {
        this.id = id;
        this.legalName = legalName;
        this.currency = currency;
        this.timeZone = timeZone;
        this.timeZoneId = timeZoneId;
    }

    public static CompanyResponse from(Company company) {
        return new CompanyResponse(
                company.getId(),
                company.getLegalName(),
                company.getCurrency().name(),
                company.getTimeZone().name(),
                company.getTimeZone().zoneId()
        );
    }

    public Long getId() {
        return id;
    }

    public String getLegalName() {
        return legalName;
    }

    public String getCurrency() {
        return currency;
    }

    public String getTimeZone() {
        return timeZone;
    }

    public String getTimeZoneId() {
        return timeZoneId;
    }
}
