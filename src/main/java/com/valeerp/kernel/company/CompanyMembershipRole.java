package com.valeerp.kernel.company;

import com.valeerp.kernel.DomainException;

/**
 * Rol de pertenencia de un usuario a una compañía.
 */
public enum CompanyMembershipRole {
    OWNER,
    ADMIN,
    MEMBER;

    public static CompanyMembershipRole require(String value) {
        if (value == null || value.isBlank()) {
            throw new DomainException("El rol de pertenencia es obligatorio");
        }
        try {
            return CompanyMembershipRole.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new DomainException("Rol de pertenencia no soportado: " + value);
        }
    }
}
