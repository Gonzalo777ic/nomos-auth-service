package com.valeerp.kernel.company;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Defaults de compañía vía configuración. Sin literales en controladores.
 * Prefijo: valeerp.company
 */
@ConfigurationProperties(prefix = "valeerp.company")
public class CompanyProperties {

    private CompanyCurrency defaultCurrency = CompanyCurrency.PEN;
    private CompanyTimeZone defaultTimeZone = CompanyTimeZone.AMERICA_LIMA;
    private CompanyMembershipRole defaultMembershipRole = CompanyMembershipRole.MEMBER;

    public CompanyCurrency getDefaultCurrency() {
        return defaultCurrency;
    }

    public void setDefaultCurrency(CompanyCurrency defaultCurrency) {
        this.defaultCurrency = defaultCurrency == null ? CompanyCurrency.PEN : defaultCurrency;
    }

    public CompanyTimeZone getDefaultTimeZone() {
        return defaultTimeZone;
    }

    public void setDefaultTimeZone(CompanyTimeZone defaultTimeZone) {
        this.defaultTimeZone = defaultTimeZone == null ? CompanyTimeZone.AMERICA_LIMA : defaultTimeZone;
    }

    public CompanyMembershipRole getDefaultMembershipRole() {
        return defaultMembershipRole;
    }

    public void setDefaultMembershipRole(CompanyMembershipRole defaultMembershipRole) {
        this.defaultMembershipRole = defaultMembershipRole == null
                ? CompanyMembershipRole.MEMBER
                : defaultMembershipRole;
    }
}
