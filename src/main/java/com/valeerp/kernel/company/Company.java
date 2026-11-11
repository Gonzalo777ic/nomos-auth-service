package com.valeerp.kernel.company;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.SoftDeletable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "companies")
public class Company extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "legal_name", nullable = false, length = 255)
    private String legalName;

    @Enumerated(EnumType.STRING)
    @Column(name = "currency", nullable = false, length = 8)
    private CompanyCurrency currency;

    @Enumerated(EnumType.STRING)
    @Column(name = "time_zone", nullable = false, length = 64)
    private CompanyTimeZone timeZone;

    protected Company() {
    }

    public static Company register(String legalName, CompanyCurrency currency, CompanyTimeZone timeZone) {
        Company company = new Company();
        company.rename(legalName);
        company.changeCurrency(currency);
        company.changeTimeZone(timeZone);
        return company;
    }

    public void rename(String legalName) {
        if (legalName == null || legalName.isBlank()) {
            throw new DomainException("La razón social es obligatoria");
        }
        this.legalName = legalName.trim();
    }

    public void changeCurrency(CompanyCurrency currency) {
        if (currency == null) {
            throw new DomainException("La moneda es obligatoria");
        }
        this.currency = currency;
    }

    public void changeTimeZone(CompanyTimeZone timeZone) {
        if (timeZone == null) {
            throw new DomainException("La zona horaria es obligatoria");
        }
        this.timeZone = timeZone;
    }

    public Long getId() {
        return id;
    }

    public String getLegalName() {
        return legalName;
    }

    public CompanyCurrency getCurrency() {
        return currency;
    }

    public CompanyTimeZone getTimeZone() {
        return timeZone;
    }
}
