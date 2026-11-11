package com.nomos.inventory.auth.impersonation.dto;

/**
 * Respuesta DTO del stub de impersonación. Nunca expone entidad JPA.
 */
public class ImpersonationResponse {

    private final boolean allowedByPolicy;
    private final Long actorUserId;
    private final Long targetUserId;
    private final String message;

    public ImpersonationResponse(boolean allowedByPolicy, Long actorUserId, Long targetUserId, String message) {
        this.allowedByPolicy = allowedByPolicy;
        this.actorUserId = actorUserId;
        this.targetUserId = targetUserId;
        this.message = message;
    }

    public boolean isAllowedByPolicy() {
        return allowedByPolicy;
    }

    public Long getActorUserId() {
        return actorUserId;
    }

    public Long getTargetUserId() {
        return targetUserId;
    }

    public String getMessage() {
        return message;
    }
}
