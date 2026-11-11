package com.nomos.inventory.auth.impersonation.dto;

/**
 * Entrada HTTP para iniciar impersonación (stub).
 */
public class StartImpersonationRequest {

    private Long targetUserId;
    private String reason;

    public Long getTargetUserId() {
        return targetUserId;
    }

    public void setTargetUserId(Long targetUserId) {
        this.targetUserId = targetUserId;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
