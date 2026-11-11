package com.nomos.inventory.auth.acl;

import com.valeerp.kernel.DomainException;

/**
 * Apps del ERP (estilo Odoo) para claves de permiso {@code app.model.action}.
 * Política de catálogo ACL — no inventar literales en controladores.
 */
public enum ErpApp {

    IDENTITY("identity"),
    CONTACTS("contacts"),
    CATALOG("catalog"),
    INVENTORY("inventory"),
    PURCHASE("purchase"),
    SALES("sales"),
    ACCOUNTING("accounting"),
    POS("pos"),
    STORE("store"),
    HR("hr"),
    REPORTS("reports");

    private final String code;

    ErpApp(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }

    public static ErpApp require(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new DomainException("La app del permiso es obligatoria");
        }
        String normalized = raw.trim().toLowerCase();
        for (ErpApp app : values()) {
            if (app.code.equals(normalized) || app.name().equalsIgnoreCase(normalized)) {
                return app;
            }
        }
        throw new DomainException("App ACL desconocida: " + raw);
    }
}
