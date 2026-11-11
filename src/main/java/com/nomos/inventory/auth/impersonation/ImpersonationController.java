package com.nomos.inventory.auth.impersonation;

import com.nomos.inventory.auth.impersonation.dto.ImpersonationResponse;
import com.nomos.inventory.auth.impersonation.dto.StartImpersonationRequest;
import com.valeerp.kernel.DomainException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Endpoints de impersonación. El controlador solo traduce HTTP;
 * la política enabled/disabled vive en configuración vía {@link ImpersonationService}.
 */
@RestController
@RequestMapping("/api/identity/impersonation")
public class ImpersonationController {

    private final ImpersonationService impersonationService;

    public ImpersonationController(ImpersonationService impersonationService) {
        this.impersonationService = impersonationService;
    }

    @GetMapping("/policy")
    public Map<String, Object> policy() {
        return Map.of(
                "enabled", impersonationService.isEnabled(),
                "propertyKey", "valeerp.impersonation.enabled"
        );
    }

    @PostMapping("/start")
    public ResponseEntity<ImpersonationResponse> start(
            @RequestBody StartImpersonationRequest request,
            @RequestParam(name = "actorUserId", required = false) Long actorUserId
    ) {
        // Política primero: si está off, no se llega al stub de actor/sesión.
        impersonationService.refuseIfDisabled();
        if (actorUserId == null) {
            // Stub local: sin resolver JWT→userId aún; exige query explícito o falla claro.
            throw new DomainException(
                    "actorUserId es obligatorio mientras el stub no resuelve el actor desde la sesión"
            );
        }
        return ResponseEntity.ok(impersonationService.start(actorUserId, request));
    }
}
