package com.valeerp.hr;

import com.valeerp.kernel.DomainException;

/**
 * Estados del libro de ausencias. Sin delete físico: cierre/anulación por estado.
 */
public enum AbsenceStatus {

    DRAFT,
    APPROVED,
    COMPLETED,
    CANCELLED;

    public static AbsenceStatus require(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new DomainException("El estado de ausencia es obligatorio");
        }
        try {
            return AbsenceStatus.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new DomainException("Estado de ausencia desconocido: " + raw);
        }
    }
}
