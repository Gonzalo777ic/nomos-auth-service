package com.nomos.inventory.auth.acl.dto;

public class LoginResponse {

    private final String token;
    private final Long sessionId;
    private final AccessSnapshotResponse access;

    public LoginResponse(String token, Long sessionId, AccessSnapshotResponse access) {
        this.token = token;
        this.sessionId = sessionId;
        this.access = access;
    }

    public String getToken() {
        return token;
    }

    public Long getSessionId() {
        return sessionId;
    }

    public AccessSnapshotResponse getAccess() {
        return access;
    }
}
