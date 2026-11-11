package com.valeerp.kernel.company;

import com.valeerp.kernel.DomainException;

/**
 * Monedas soportadas por compañía. PEN es la moneda piloto del ERP.
 */
public enum CompanyCurrency {
    PEN,
    USD,
    EUR;

    public static CompanyCurrency require(String code) {
        if (code == null || code.isBlank()) {
            throw new DomainException("La moneda es obligatoria");
        }
        try {
            return CompanyCurrency.valueOf(code.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new DomainException("Moneda no soportada: " + code);
        }
    }
}
