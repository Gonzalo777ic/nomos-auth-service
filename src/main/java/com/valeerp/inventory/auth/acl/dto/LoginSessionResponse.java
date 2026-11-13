package com.valeerp.inventory.auth.acl.dto;

import com.valeerp.inventory.auth.acl.LoginSession;

import java.time.Instant;

public class LoginSessionResponse {

    private final Long id;
    private final Long userId;
    private final String username;
    private final Instant startedAt;
    private final Instant endedAt;
    private final String status;
    private final String clientIp;
    private final String userAgent;
    private final Instant voidedAt;
    private final String voidedBy;
    private final String voidReason;

    private LoginSessionResponse(
            Long id,
            Long userId,
            String username,
            Instant startedAt,
            Instant endedAt,
            String status,
            String clientIp,
            String userAgent,
            Instant voidedAt,
            String voidedBy,
            String voidReason
    ) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.startedAt = startedAt;
        this.endedAt = endedAt;
        this.status = status;
        this.clientIp = clientIp;
        this.userAgent = userAgent;
        this.voidedAt = voidedAt;
        this.voidedBy = voidedBy;
        this.voidReason = voidReason;
    }

    public static LoginSessionResponse from(LoginSession session) {
        return new LoginSessionResponse(
                session.getId(),
                session.getUserId(),
                session.getUsername(),
                session.getStartedAt(),
                session.getEndedAt(),
                session.getStatus().name(),
                session.getClientIp(),
                session.getUserAgent(),
                session.getVoidedAt(),
                session.getVoidedBy(),
                session.getVoidReason()
        );
    }

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getEndedAt() {
        return endedAt;
    }

    public String getStatus() {
        return status;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public Instant getVoidedAt() {
        return voidedAt;
    }

    public String getVoidedBy() {
        return voidedBy;
    }

    public String getVoidReason() {
        return voidReason;
    }
}
