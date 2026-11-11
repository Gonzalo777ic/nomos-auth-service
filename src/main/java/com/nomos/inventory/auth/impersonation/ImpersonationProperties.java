package com.nomos.inventory.auth.impersonation;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Política de impersonación. Fuente de verdad: configuración / env, no un boolean en el caso de uso.
 * Prefijo: {@code valeerp.impersonation}
 * <p>
 * Deshabilitada por defecto. Activar solo con {@code valeerp.impersonation.enabled=true}
 * o {@code VALEERP_IMPERSONATION_ENABLED=true}.
 */
@ConfigurationProperties(prefix = "valeerp.impersonation")
public class ImpersonationProperties {

    /**
     * Si es {@code false} (default), el caso de uso rechaza cualquier intento de impersonar.
     */
    private boolean enabled = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
