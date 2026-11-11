package com.valeerp.hr;

import com.valeerp.kernel.DomainException;

/**
 * Política de tipos de contrato laboral. Catálogo local RRHH.
 */
public enum ContractType {

    INDEFINITE,
    FIXED_TERM,
    INTERNSHIP,
    SERVICES;

    public static ContractType require(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new DomainException("El tipo de contrato es obligatorio");
        }
        try {
            return ContractType.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new DomainException("Tipo de contrato no soportado: " + raw);
        }
    }
}
