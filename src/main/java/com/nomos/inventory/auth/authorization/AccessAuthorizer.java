package com.nomos.inventory.auth.authorization;

import com.nomos.inventory.auth.model.User;
import com.valeerp.kernel.DomainException;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;

/**
 * Decisión de autorización por permisos efectivos (roles y/o grupos ACL).
 * Puro dominio: sin Auth0, sin HTTP, sin otros servicios.
 */
public final class AccessAuthorizer {

    private AccessAuthorizer() {
    }

    public static boolean allows(Collection<String> grantedPermissionCodes, String requiredPermissionCode) {
        requireCode(requiredPermissionCode);
        if (grantedPermissionCodes == null || grantedPermissionCodes.isEmpty()) {
            return false;
        }
        String required = requiredPermissionCode.trim();
        for (String granted : grantedPermissionCodes) {
            if (granted != null && required.equals(granted.trim())) {
                return true;
            }
        }
        return false;
    }

    public static boolean allows(User user, String requiredPermissionCode) {
        if (user == null) {
            throw new DomainException("El usuario a autorizar es obligatorio");
        }
        if (user.isRetired()) {
            return false;
        }
        return allows(user.effectivePermissionCodes(), requiredPermissionCode);
    }

    public static void require(Collection<String> grantedPermissionCodes, String requiredPermissionCode) {
        if (!allows(grantedPermissionCodes, requiredPermissionCode)) {
            throw new DomainException("Permiso denegado: " + requiredPermissionCode);
        }
    }

    public static void require(User user, String requiredPermissionCode) {
        if (!allows(user, requiredPermissionCode)) {
            throw new DomainException("Permiso denegado: " + requiredPermissionCode);
        }
    }

    public static Set<String> snapshot(User user) {
        if (user == null) {
            throw new DomainException("El usuario a autorizar es obligatorio");
        }
        return Set.copyOf(user.effectivePermissionCodes());
    }

    private static void requireCode(String requiredPermissionCode) {
        if (requiredPermissionCode == null || requiredPermissionCode.isBlank()) {
            throw new DomainException("El permiso requerido es obligatorio");
        }
        Objects.requireNonNull(requiredPermissionCode);
    }
}
