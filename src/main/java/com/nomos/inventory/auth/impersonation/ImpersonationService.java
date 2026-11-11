package com.nomos.inventory.auth.impersonation;

import com.nomos.inventory.auth.impersonation.dto.ImpersonationResponse;
import com.nomos.inventory.auth.impersonation.dto.StartImpersonationRequest;
import com.valeerp.kernel.DomainException;
import org.springframework.stereotype.Service;

/**
 * Caso de uso de impersonación. La política de habilitación sale de
 * {@link ImpersonationProperties} (config/env), no de un literal en este servicio.
 * <p>
 * Stub: cuando la política está activa valida la entrada y responde un DTO;
 * el cambio real de sesión/token queda para una iteración posterior.
 */
@Service
public class ImpersonationService {

    private static final String STUB_MESSAGE =
            "Impersonación permitida por política; el cambio de sesión aún es stub.";

    private final ImpersonationProperties properties;

    public ImpersonationService(ImpersonationProperties properties) {
        this.properties = properties;
    }

    public boolean isEnabled() {
        return properties.isEnabled();
    }

    /**
     * Inicia impersonación si la política lo permite.
     *
     * @param actorUserId id del usuario autenticado que intenta impersonar
     * @param request     destino y motivo
     */
    public ImpersonationResponse start(Long actorUserId, StartImpersonationRequest request) {
        refuseIfDisabled();
        if (actorUserId == null) {
            throw new DomainException("El actor de impersonación es obligatorio");
        }
        if (request == null || request.getTargetUserId() == null) {
            throw new DomainException("El usuario objetivo de impersonación es obligatorio");
        }
        if (actorUserId.equals(request.getTargetUserId())) {
            throw new DomainException("No se puede impersonar al mismo usuario");
        }
        return new ImpersonationResponse(true, actorUserId, request.getTargetUserId(), STUB_MESSAGE);
    }

    public void refuseIfDisabled() {
        if (!properties.isEnabled()) {
            throw new DomainException(
                    "La impersonación está deshabilitada por política (valeerp.impersonation.enabled=false)"
            );
        }
    }
}
