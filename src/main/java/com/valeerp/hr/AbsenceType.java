package com.valeerp.hr;

import com.valeerp.kernel.DomainException;

/**
 * Política de tipos de ausencia. Catálogo local RRHH.
 */
public enum AbsenceType {

    VACATION,
    SICK,
    PERSONAL,
    UNPAID,
    OTHER;

    public static AbsenceType require(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new DomainException("El tipo de ausencia es obligatorio");
        }
        try {
            return AbsenceType.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new DomainException("Tipo de ausencia no soportado: " + raw);
        }
    }
}
