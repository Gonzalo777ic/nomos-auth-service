package com.valeerp.hr;

import com.valeerp.kernel.Currency;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Defaults de política RRHH vía configuración. Sin literales en controladores.
 * Prefijo: valeerp.hr
 */
@ConfigurationProperties(prefix = "valeerp.hr")
public class HrProperties {

    private String defaultWageCurrency = Currency.PEN.code();
    private ContractType defaultContractType = ContractType.INDEFINITE;
    private AbsenceType defaultAbsenceType = AbsenceType.VACATION;

    public Currency getDefaultWageCurrency() {
        return Currency.of(defaultWageCurrency);
    }

    public void setDefaultWageCurrency(String defaultWageCurrency) {
        this.defaultWageCurrency = (defaultWageCurrency == null || defaultWageCurrency.isBlank())
                ? Currency.PEN.code()
                : defaultWageCurrency.trim().toUpperCase();
    }

    public ContractType getDefaultContractType() {
        return defaultContractType == null ? ContractType.INDEFINITE : defaultContractType;
    }

    public void setDefaultContractType(ContractType defaultContractType) {
        this.defaultContractType = defaultContractType == null ? ContractType.INDEFINITE : defaultContractType;
    }

    public AbsenceType getDefaultAbsenceType() {
        return defaultAbsenceType == null ? AbsenceType.VACATION : defaultAbsenceType;
    }

    public void setDefaultAbsenceType(AbsenceType defaultAbsenceType) {
        this.defaultAbsenceType = defaultAbsenceType == null ? AbsenceType.VACATION : defaultAbsenceType;
    }
}
