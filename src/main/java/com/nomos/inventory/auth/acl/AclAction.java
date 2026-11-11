package com.nomos.inventory.auth.acl;

import com.valeerp.kernel.DomainException;

/**
 * Acciones granulares estilo Odoo (ir.model.access): create/read/write/unlink.
 */
public enum AclAction {

    CREATE("create"),
    READ("read"),
    WRITE("write"),
    UNLINK("unlink");

    private final String code;

    AclAction(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }

    public static AclAction require(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new DomainException("La acción ACL es obligatoria");
        }
        String normalized = raw.trim().toLowerCase();
        for (AclAction action : values()) {
            if (action.code.equals(normalized) || action.name().equalsIgnoreCase(normalized)) {
                return action;
            }
        }
        throw new DomainException("Acción ACL desconocida: " + raw);
    }
}
