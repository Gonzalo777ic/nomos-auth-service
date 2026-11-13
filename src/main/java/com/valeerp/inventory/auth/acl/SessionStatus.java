package com.valeerp.inventory.auth.acl;

import com.valeerp.kernel.DomainException;

/**
 * Estado del libro de sesión. La anulación no oculta filas: VOIDED permanece consultable.
 */
public enum SessionStatus {

    ACTIVE,
    VOIDED;

    public static SessionStatus require(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new DomainException("El estado de sesión es obligatorio");
        }
        try {
            return SessionStatus.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new DomainException("Estado de sesión desconocido: " + raw);
        }
    }
}
