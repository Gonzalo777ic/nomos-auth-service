package com.nomos.inventory.auth.impersonation;

import com.nomos.inventory.auth.impersonation.dto.ImpersonationResponse;
import com.nomos.inventory.auth.impersonation.dto.StartImpersonationRequest;
import com.valeerp.kernel.DomainException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Política de impersonación con fixtures: el flag de configuración es la fuente de verdad.
 */
class ImpersonationServiceTest {

    @Test
    void refusesWhenPolicyDisabledByDefault() {
        ImpersonationProperties properties = new ImpersonationProperties();
        assertFalse(properties.isEnabled());

        ImpersonationService service = new ImpersonationService(properties);
        StartImpersonationRequest request = new StartImpersonationRequest();
        request.setTargetUserId(99L);
        request.setReason("soporte");

        DomainException denied = assertThrows(
                DomainException.class,
                () -> service.start(1L, request)
        );
        assertTrue(denied.getMessage().contains("valeerp.impersonation.enabled"));
    }

    @Test
    void allowsStubWhenPolicyEnabledViaConfiguration() {
        ImpersonationProperties properties = new ImpersonationProperties();
        properties.setEnabled(true);

        ImpersonationService service = new ImpersonationService(properties);
        StartImpersonationRequest request = new StartImpersonationRequest();
        request.setTargetUserId(42L);
        request.setReason("auditoría");

        ImpersonationResponse response = service.start(7L, request);

        assertTrue(response.isAllowedByPolicy());
        assertEquals(7L, response.getActorUserId());
        assertEquals(42L, response.getTargetUserId());
    }

    @Test
    void rejectsSelfImpersonationEvenWhenEnabled() {
        ImpersonationProperties properties = new ImpersonationProperties();
        properties.setEnabled(true);
        ImpersonationService service = new ImpersonationService(properties);

        StartImpersonationRequest request = new StartImpersonationRequest();
        request.setTargetUserId(7L);

        assertThrows(DomainException.class, () -> service.start(7L, request));
    }
}
